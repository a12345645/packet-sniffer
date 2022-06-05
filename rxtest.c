#include <linux/if.h>
#include <linux/if_ether.h> /* The L2 protocols */
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <unistd.h>

typedef struct _rxring *rxring_t;
typedef int (*rx_cb_t)(void *u, const uint8_t *buf, size_t len);

struct priv {
    /* unused */
};

struct _rxring {
    void *user;
    rx_cb_t cb;
    uint8_t *map;
    size_t map_sz;
    sig_atomic_t cancel;
    unsigned int r_idx, nr_blocks, block_sz;
    int ifindex;
    int fd;
};

#define N_BLOCKS 2049

/* 1. Open the packet socket */
static bool packet_socket(rxring_t rx)
{
    return (rx->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) >= 0;
}

/* 2. Set TPACKET_V3 */
static bool set_v3(rxring_t rx)
{
    int val = TPACKET_V3;
    return !setsockopt(rx->fd, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
}

/* 3. Setup the fd for mmap() ring buffer */
static bool rx_ring(rxring_t rx)
{
    struct tpacket_req3 req = {
        .tp_block_size = getpagesize() << 2,
        .tp_block_nr = N_BLOCKS,
        .tp_frame_size = TPACKET_ALIGNMENT << 7,
        .tp_frame_nr = req.tp_block_size / req.tp_frame_size * req.tp_block_nr,
        .tp_retire_blk_tov = 64,
        .tp_sizeof_priv = sizeof(struct priv),
        .tp_feature_req_word = 0,
    };
    if (setsockopt(rx->fd, SOL_PACKET, PACKET_RX_RING, (char *) &req,
                   sizeof(req)))
        return false;

    rx->map_sz = req.tp_block_size * req.tp_block_nr;
    rx->nr_blocks = req.tp_block_nr;
    rx->block_sz = req.tp_block_size;
    return true;
}

/* 4. Bind to the ifindex on our sending interface */
static bool bind_if(rxring_t rx, const char *ifname)
{
    if (ifname) {
        struct ifreq ifr;
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
        if (ioctl(rx->fd, SIOCGIFINDEX, &ifr))
            return false;

        rx->ifindex = ifr.ifr_ifindex;
    } else {
        rx->ifindex = 0; /* interface "any" */
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = rx->ifindex;
    if (bind(rx->fd, (struct sockaddr *) &sll, sizeof(sll)))
        return false;

    return true;
}

/* 5. finally mmap() the sucker */
static bool map_ring(rxring_t rx)
{
    printf("mapping %zu MiB ring buffer\n", rx->map_sz >> 20);
    int flags = PROT_READ | PROT_WRITE;
    rx->map = mmap(NULL, rx->map_sz, flags, MAP_SHARED, rx->fd, 0);
    return rx->map != MAP_FAILED;
}

rxring_t rxring_init(const char *ifname, rx_cb_t cb, void *user)
{
    struct _rxring *rx = calloc(1, sizeof(*rx));
    if (!rx)
        goto out;

    if (!packet_socket(rx))
        goto out_free;
    if (!set_v3(rx))
        goto out_close;
    if (!rx_ring(rx))
        goto out_close;
    if (!bind_if(rx, ifname))
        goto out_close;
    if (!map_ring(rx))
        goto out_close;

    rx->cb = cb;
    rx->user = user;

    /* success */
    goto out;

out_close:
    close(rx->fd);
out_free:
    free(rx);
    rx = NULL;
out:
    return rx;
}

bool rxring_fanout_hash(rxring_t rx, uint16_t id)
{
    int val = PACKET_FANOUT_FLAG_DEFRAG | (PACKET_FANOUT_HASH << 16) | id;
    return !setsockopt(rx->fd, SOL_PACKET, PACKET_FANOUT, &val, sizeof(val));
}

static void do_block(rxring_t rx, struct tpacket_block_desc *desc)
{
    const uint8_t *ptr = (uint8_t *) desc + desc->hdr.bh1.offset_to_first_pkt;
    unsigned int num_pkts = desc->hdr.bh1.num_pkts;

    for (unsigned int i = 0; i < num_pkts; i++) {
        struct tpacket3_hdr *hdr = (struct tpacket3_hdr *) ptr;
        printf("packet %u/%u %u.%u\n", i, num_pkts, hdr->tp_sec, hdr->tp_nsec);

        /* packet */
        if (rx->cb)
            (*rx->cb)(rx->user, ptr + hdr->tp_mac, hdr->tp_snaplen);

        ptr += hdr->tp_next_offset;
        //__sync_synchronize();
    }
}

void rxring_mainloop(rxring_t rx)
{
    struct pollfd pfd = {
        .fd = rx->fd,
        .events = POLLIN | POLLERR,
        .revents = 0,
    };
    while (!rx->cancel) {
        struct tpacket_block_desc *desc =
            (struct tpacket_block_desc *) rx->map + rx->r_idx * rx->block_sz;

        while (!(desc->hdr.bh1.block_status & TP_STATUS_USER))
            poll(&pfd, 1, -1);

        /* walk block */
        do_block(rx, desc);

        desc->hdr.bh1.block_status = TP_STATUS_KERNEL;
        __sync_synchronize();
        rx->r_idx = (rx->r_idx + 1) % rx->nr_blocks;
    }
}

void rxring_free(rxring_t rx)
{
    if (!rx)
        return;

    munmap(rx->map, rx->map_sz);
    close(rx->fd);
    free(rx);
}

#include <ctype.h>
static void hex_dumpf(FILE *f, const uint8_t *tmp, size_t len, size_t llen)
{
    if (!f || 0 == len)
        return;

    if (!llen)
        llen = 0x10;
    for (size_t line, i, j = 0; j < len; j += line, tmp += line) {
        line = (j + llen > len) ? len - j : llen;
        fprintf(f, " | %05zx : ", j);
        for (i = 0; i < line; i++)
            fprintf(f, "%c", isprint(tmp[i]) ? tmp[i] : '.');
        for (; i < llen; i++)
            fprintf(f, " ");
        for (i = 0; i < line; i++)
            fprintf(f, " %02x", tmp[i]);
        fprintf(f, "\n");
    }
    fprintf(f, "\n");
}

static int cb(void *u, const uint8_t *buf, size_t len)
{
    hex_dumpf(stdout, buf, len, 0);
    return 1;
}

int main(int argc, char **argv)
{
    const char *cmd = argv[0];
    if (argc < 2) {
        fprintf(stderr, "Usage:\n\t%s <ifname>\n\n", cmd);
        return EXIT_FAILURE;
    }

    rxring_t rx = rxring_init(argv[1], cb, NULL);
    if (!rx || !rxring_fanout_hash(rx, 0x1234))
        return EXIT_FAILURE;

    rxring_mainloop(rx);

    printf("%s: OK\n", cmd);
    rxring_free(rx);

    return EXIT_SUCCESS;
}