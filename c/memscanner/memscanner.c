/*
 * RecurSec Memory Scanner — fast memory-mapped pattern scanning.
 *
 * Scans files using memory-mapped I/O for maximum throughput.
 * Used by the agent to quickly scan:
 * 1. Large log files for IoC patterns
 * 2. Binary files for strings/signatures
 * 3. Config files for secrets
 * 4. Tool output files for findings
 *
 * Reads patterns from a file (one regex per line) and scans
 * input files, outputting matches as JSON.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <regex.h>

#define MAX_PATTERNS 256
#define MAX_LINE_LEN 4096
#define MAX_MATCH_LEN 512

typedef struct {
    char name[128];
    char pattern_str[512];
    regex_t compiled;
    char severity[16];
    int valid;
} Pattern;

typedef struct {
    char pattern_name[128];
    char severity[16];
    size_t line_number;
    size_t offset;
    char match_text[MAX_MATCH_LEN];
    char file_path[256];
} Match;

typedef struct {
    size_t total_matches;
    size_t files_scanned;
    size_t bytes_scanned;
    size_t lines_scanned;
    double duration_ms;
} ScanStats;

/* Built-in patterns for quick scanning */
static const char *builtin_patterns[][3] = {
    {"AWS Key",       "AKIA[0-9A-Z]\\{16\\}",                     "critical"},
    {"Private Key",   "-----BEGIN.*PRIVATE KEY-----",              "critical"},
    {"Password",      "[Pp]assword[[:space:]]*[:=][[:space:]]*.",  "high"},
    {"IP Address",    "[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}\\.[0-9]\\{1,3\\}", "info"},
    {"Email",         "[a-zA-Z0-9._%+-]\\{1,\\}@[a-zA-Z0-9.-]\\{1,\\}", "info"},
    {"TODO/FIXME",    "\\(TODO\\|FIXME\\|HACK\\|XXX\\)",          "info"},
    {"Shell Command", "\\(system\\|exec\\|popen\\|eval\\)(.*)",   "high"},
    {"SQL Query",     "\\(SELECT\\|INSERT\\|UPDATE\\|DELETE\\|DROP\\).*\\(FROM\\|INTO\\|SET\\|TABLE\\)", "medium"},
    {NULL, NULL, NULL}
};

static Pattern patterns[MAX_PATTERNS];
static int pattern_count = 0;
static ScanStats stats = {0};

int add_pattern(const char *name, const char *regex_str, const char *severity) {
    if (pattern_count >= MAX_PATTERNS) return -1;

    Pattern *p = &patterns[pattern_count];
    strncpy(p->name, name, sizeof(p->name) - 1);
    strncpy(p->pattern_str, regex_str, sizeof(p->pattern_str) - 1);
    strncpy(p->severity, severity, sizeof(p->severity) - 1);

    int ret = regcomp(&p->compiled, regex_str, REG_EXTENDED | REG_ICASE | REG_NEWLINE);
    if (ret != 0) {
        char errbuf[256];
        regerror(ret, &p->compiled, errbuf, sizeof(errbuf));
        fprintf(stderr, "Warning: pattern '%s' failed to compile: %s\n", name, errbuf);
        p->valid = 0;
        return -1;
    }
    p->valid = 1;
    pattern_count++;
    return 0;
}

void load_builtin_patterns(void) {
    for (int i = 0; builtin_patterns[i][0] != NULL; i++) {
        add_pattern(builtin_patterns[i][0], builtin_patterns[i][1], builtin_patterns[i][2]);
    }
}

int load_patterns_from_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Cannot open patterns file: %s\n", path);
        return -1;
    }

    char line[1024];
    int loaded = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        /* Format: name|regex|severity */
        char *name = strtok(line, "|");
        char *regex = strtok(NULL, "|");
        char *severity = strtok(NULL, "|\n");
        if (name && regex && severity) {
            /* Trim whitespace */
            while (*name == ' ') name++;
            while (*regex == ' ') regex++;
            while (*severity == ' ') severity++;
            char *end = severity + strlen(severity) - 1;
            while (end > severity && (*end == '\n' || *end == '\r' || *end == ' ')) {
                *end = '\0';
                end--;
            }
            if (add_pattern(name, regex, severity) == 0) {
                loaded++;
            }
        }
    }
    fclose(f);
    return loaded;
}

void print_match_json(const Match *m) {
    printf("{\"pattern\":\"%s\",\"severity\":\"%s\",\"line\":%zu,"
           "\"offset\":%zu,\"file\":\"%s\",\"match\":\"",
           m->pattern_name, m->severity, m->line_number,
           m->offset, m->file_path);
    /* Escape JSON special chars in match text */
    for (const char *c = m->match_text; *c; c++) {
        switch (*c) {
            case '"': printf("\\\""); break;
            case '\\': printf("\\\\"); break;
            case '\n': printf("\\n"); break;
            case '\r': printf("\\r"); break;
            case '\t': printf("\\t"); break;
            default:
                if ((unsigned char)*c >= 0x20) {
                    putchar(*c);
                }
                break;
        }
    }
    printf("\"}\n");
}

size_t scan_buffer(const char *data, size_t len, const char *filepath) {
    size_t matches = 0;
    size_t line_num = 1;
    const char *line_start = data;

    for (size_t i = 0; i <= len; i++) {
        if (i == len || data[i] == '\n') {
            size_t line_len = (i == len) ? (size_t)(&data[i] - line_start) : (size_t)(&data[i] - line_start);
            if (line_len > 0 && line_len < MAX_LINE_LEN) {
                char line_buf[MAX_LINE_LEN];
                size_t copy_len = line_len < MAX_LINE_LEN - 1 ? line_len : MAX_LINE_LEN - 1;
                memcpy(line_buf, line_start, copy_len);
                line_buf[copy_len] = '\0';

                for (int p = 0; p < pattern_count; p++) {
                    if (!patterns[p].valid) continue;
                    regmatch_t pmatch[1];
                    if (regexec(&patterns[p].compiled, line_buf, 1, pmatch, 0) == 0) {
                        Match m = {0};
                        strncpy(m.pattern_name, patterns[p].name, sizeof(m.pattern_name) - 1);
                        strncpy(m.severity, patterns[p].severity, sizeof(m.severity) - 1);
                        m.line_number = line_num;
                        m.offset = (size_t)(line_start - data) + (size_t)pmatch[0].rm_so;
                        strncpy(m.file_path, filepath, sizeof(m.file_path) - 1);

                        int match_len = pmatch[0].rm_eo - pmatch[0].rm_so;
                        if (match_len > MAX_MATCH_LEN - 1) match_len = MAX_MATCH_LEN - 1;
                        memcpy(m.match_text, line_buf + pmatch[0].rm_so, (size_t)match_len);
                        m.match_text[match_len] = '\0';

                        print_match_json(&m);
                        matches++;
                    }
                }
                stats.lines_scanned++;
            }
            line_start = &data[i + 1];
            line_num++;
        }
    }
    return matches;
}

int scan_file(const char *filepath) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open file: %s (%s)\n", filepath, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    if (st.st_size == 0) {
        close(fd);
        return 0;
    }

    /* Memory-map the file for fast scanning */
    void *data = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        /* Fall back to read-based scanning */
        char *buf = malloc((size_t)st.st_size + 1);
        if (!buf) {
            close(fd);
            return -1;
        }
        ssize_t n = read(fd, buf, (size_t)st.st_size);
        close(fd);
        if (n <= 0) {
            free(buf);
            return -1;
        }
        buf[n] = '\0';
        size_t matches = scan_buffer(buf, (size_t)n, filepath);
        free(buf);
        stats.bytes_scanned += (size_t)st.st_size;
        stats.files_scanned++;
        stats.total_matches += matches;
        return (int)matches;
    }

    close(fd);
    size_t matches = scan_buffer((const char *)data, (size_t)st.st_size, filepath);
    munmap(data, (size_t)st.st_size);

    stats.bytes_scanned += (size_t)st.st_size;
    stats.files_scanned++;
    stats.total_matches += matches;
    return (int)matches;
}

void print_stats(void) {
    fprintf(stderr, "\n--- Scan Statistics ---\n");
    fprintf(stderr, "Files scanned:  %zu\n", stats.files_scanned);
    fprintf(stderr, "Bytes scanned:  %zu (%.2f MB)\n",
            stats.bytes_scanned, (double)stats.bytes_scanned / (1024 * 1024));
    fprintf(stderr, "Lines scanned:  %zu\n", stats.lines_scanned);
    fprintf(stderr, "Total matches:  %zu\n", stats.total_matches);
    fprintf(stderr, "Patterns loaded: %d\n", pattern_count);
    fprintf(stderr, "Duration:       %.2f ms\n", stats.duration_ms);
    if (stats.duration_ms > 0) {
        fprintf(stderr, "Throughput:     %.2f MB/s\n",
                ((double)stats.bytes_scanned / (1024 * 1024)) / (stats.duration_ms / 1000.0));
    }
}

int main(int argc, char *argv[]) {
    int use_builtin = 1;
    const char *patterns_file = NULL;
    int show_stats = 0;

    /* Parse arguments */
    int file_start = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--patterns") == 0 && i + 1 < argc) {
            patterns_file = argv[++i];
            file_start = i + 1;
        } else if (strcmp(argv[i], "--no-builtin") == 0) {
            use_builtin = 0;
            file_start = i + 1;
        } else if (strcmp(argv[i], "--stats") == 0) {
            show_stats = 1;
            file_start = i + 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: memscanner [options] <file1> [file2] ...\n"
                   "Options:\n"
                   "  --patterns <file>  Load patterns from file (name|regex|severity)\n"
                   "  --no-builtin       Don't use built-in patterns\n"
                   "  --stats            Show scan statistics on stderr\n"
                   "  --help             Show this help\n"
                   "\nReads from stdin if no files specified.\n");
            return 0;
        } else {
            break;
        }
    }

    /* Load patterns */
    if (use_builtin) {
        load_builtin_patterns();
    }
    if (patterns_file) {
        int loaded = load_patterns_from_file(patterns_file);
        if (loaded >= 0) {
            fprintf(stderr, "Loaded %d patterns from %s\n", loaded, patterns_file);
        }
    }

    if (pattern_count == 0) {
        fprintf(stderr, "No patterns loaded. Use --patterns or enable builtin patterns.\n");
        return 1;
    }

    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    /* Scan files */
    if (file_start >= argc) {
        /* Read from stdin */
        char buf[65536];
        size_t total = 0;
        char *input = NULL;
        size_t input_size = 0;
        while ((total = fread(buf, 1, sizeof(buf), stdin)) > 0) {
            input = realloc(input, input_size + total + 1);
            memcpy(input + input_size, buf, total);
            input_size += total;
        }
        if (input) {
            input[input_size] = '\0';
            scan_buffer(input, input_size, "stdin");
            stats.bytes_scanned += input_size;
            stats.files_scanned++;
            free(input);
        }
    } else {
        for (int i = file_start; i < argc; i++) {
            scan_file(argv[i]);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    stats.duration_ms = (double)(end_ts.tv_sec - start_ts.tv_sec) * 1000.0 +
                        (double)(end_ts.tv_nsec - start_ts.tv_nsec) / 1000000.0;

    if (show_stats) {
        print_stats();
    }

    /* Cleanup compiled patterns */
    for (int i = 0; i < pattern_count; i++) {
        if (patterns[i].valid) {
            regfree(&patterns[i].compiled);
        }
    }

    return stats.total_matches > 0 ? 0 : 1;
}
