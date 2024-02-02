/**
 * Basic unit testing for random implementation, using Fourmilab's ent.
 *
 * Note that this is not a set of "true" randomness unit tests, the way
 * DieHard is. It's intended to quickly expose pathological and trivial
 * bugs and to test the API.
 *
 * We definitely should look into a true random unit test (TestU01,
 * DieHard, DieHarder...)
 */

#include <runtime.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include "../test_utils.h"

/* Number of random bytes to output for test. */
#define BSLEN 16384
/* Number of bytes used by gen_bytestream's internal buffer */
#define INTERNAL_BUFLEN 1024
/* Number of values that ent gives out. */
#define ENT_NSTATS 6
/* Length of a stat entry key */
#define KEY_LEN 64

/* Maximum acceptable compressibility value for a reasonably long bytestream */
#define COMPRESS_PASS_THRESH 10
/* Minimum acceptable deviation from expected mean (127.5 in our case) */
#define MEAN_DEV_THRESH 4

/* Show statistics at runtime? */
boolean show_stats = false;

struct ent_stat_entry {
    char key[64];
    double val;
};

/**
 * Cleanup function: remove the bytestream file at path.
 */
static void rm_bytestream(char *path)
{
    remove(path);
}

static int write_chunk(int fd, u64 *buf, int len)
{
    int nbytes = 0, off = 0;
    int err;

    while (off < len) {
        nbytes = write(fd, &buf[off], len - off);
        if (nbytes < 0) {
            if (errno == EINTR)
                continue;
            else {
                err = errno;
                printf("error: %s\n", strerror(err));
                return -1;
            }
        }

        off += nbytes;
    }

    return 0;
}

/**
 * Generate a bytestream of <len> random bytes in a file at path.
 *
 * TODO: buffer assumes len > 1024.
 */
static void gen_bytestream(char *path, int len)
{
    int fd, err;
    u64 buf[INTERNAL_BUFLEN / 8];
    u64 i, nbytes = 0;

    fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd == -1) {
        test_perror("can't create bytestream file");
    }

    while (nbytes < BSLEN) {
        for (i = 0; i < INTERNAL_BUFLEN / 8; i++)
            buf[i] = random_u64();

        nbytes += INTERNAL_BUFLEN;

        err = write_chunk(fd, &buf[0], INTERNAL_BUFLEN);
        if (err == -1) {
            close(fd);
            rm_bytestream(path);
            exit(EXIT_FAILURE);
        }
    }

    close(fd);
}

/**
 * Get statistics about the stream via ent.
 */
static int ent_get_stats(char *path, struct ent_stat_entry *stats)
{
    char ent_cmd[1024], ent_buf[1024];
    char *s;
    int matched, nfield = 0, field_len, linenum = -1;
    FILE *f;

    snprintf(&ent_cmd[0], 1024, "ent -t %s", path);

    f = popen(&ent_cmd[0], "r");
    if (!f) {
        msg_err("Can't start ent, perhaps it is not installed?\n");
        return -1;
    }

    matched = fread(&ent_buf[0], 1024, 1, f);
    if (ferror(f)) {
        pclose(f);
        msg_err("Can't read ent statistics, matched=%d.\n", matched);
        return -1;
    }

    s = &ent_buf[0];
    do {
        field_len = strcspn(s, ",\n");

        if ((nfield % (ENT_NSTATS + 1)) == 0) {
            sscanf(s, "%d", &linenum);
            s += field_len;
            nfield++;
            continue;
        }
        
        if (!field_len) {
            /* Last newline before null terminator. */
            nfield++;
            continue;
        }

        if (linenum == 0)
            snprintf(&stats[nfield].key[0], field_len + 1, "%s", s);
        else if (linenum == 1)
            sscanf(s, "%lf", &stats[nfield - (ENT_NSTATS + 1)].val);
        else if (linenum < 0) {
            msg_err("unable to parse\n");
            pclose(f);
            return -1;
        }
                     
        nfield++;

        s += field_len;
    } while (*s++);
    
    pclose(f);
    
    return 0;
}

boolean ent_stat_get(struct ent_stat_entry *stats, char *key, double *val)
{
    int i;

    for (i = 0; i < ENT_NSTATS; i++) {
        if (!strncmp(stats[i].key, key, strlen(key))) {
            *val = stats[i].val;
            return true;
        }
    }

    return false;
}

static int ent_test(struct ent_stat_entry *stats)
{
    double val;

    if (!ent_stat_get(stats, "Entropy", &val)) {
        msg_err("Cannot get bytestream entropy.\n");
        goto out_fail;
    }

    double comp = (100 * (8.0 - val)) / val;

    if (show_stats) {
        printf("Entropy: %lf\n", val);
        printf("Compressibility: %lf%%\n", comp);
    }

    if (comp > COMPRESS_PASS_THRESH) {
        msg_err("Insufficient entropy.\n");
        goto out_fail;
    }

    if (!ent_stat_get(stats, "Mean", &val)) {
        msg_err("Cannot get sequence mean\n");
        goto out_fail;
    }

    double mean_dev = 100 * (val - 127.5)/127.5;

    if (show_stats) {
        printf("Mean: %lf\n", val);
        printf("Deviation from ideal value: %lf\n", mean_dev);
    }

    if (fabs(mean_dev) > MEAN_DEV_THRESH) {
        msg_err("Mean deviation too large.\n");
        goto out_fail;
    }

    return EXIT_SUCCESS;

out_fail:
    return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
    char c;
    int err;
    int result = EXIT_SUCCESS;
    struct ent_stat_entry stats[ENT_NSTATS + 1];

    init_process_runtime();

    while ((c = getopt(argc, argv, ":s")) != -1)
    {
        switch (c) {
        case 's':
            show_stats = true;
            break;
        case '?':
            test_error("unknown option -%c", optopt);
        default:
            test_error("cannot parse arguments");
        }
    }

    memset(&stats[0], 0, sizeof stats);
    
    gen_bytestream("/tmp/test", BSLEN);
    
    err = ent_get_stats("/tmp/test", &stats[0]);
    if (err) {
        test_error("cannot get stats");
    } else {
        result = ent_test(&stats[0]);
    }
    
    rm_bytestream("/tmp/test");

    if (result != EXIT_SUCCESS)
        msg_err("Test failed.\n");

    exit(result);
}
