#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>
#include <capstone/xtensa.h>

// different platforms spit out executables
// in different places. Check a few places
// for files. The files we are looking for
// are in suite/xtensa.
static const char *locations[] = {
    NULL,
    "suite/xtensa",
    "../suite/xtensa"};

static const uint8_t *read_file(const char *name, size_t *psize)
{
    FILE *f = fopen(name, "rb");
    uint8_t *data = NULL;
    if (f)
    {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (size > 0)
        {
            data = malloc(size);
            size_t nread = fread(data, 1, size, f);
            if (nread != size)
            {
                free(data);
                data = NULL;
            }
            else
            {
                *psize = size;
            }
        }

        fclose(f);
    }

    return data;
}

static const uint8_t *try_read_file(const char *directory, const char *name, size_t *psize)
{
    if (directory && name && (strlen(directory) + strlen(name) < 64))
    {
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "%s/%s", directory, name);
        return read_file(buffer, psize);
    }
    else
    {
        return read_file(name, psize);
    }
}

static const uint8_t *try_read_file_multiple(const char *name, size_t *psize)
{
    for (int i = 0; i < sizeof(locations) / sizeof(locations[0]); i++)
    {
        const uint8_t *data = try_read_file(locations[i], name, psize);
        if (data != NULL)
        {
            return data;
        }
    }

    return NULL;
}

static size_t next_line(const char *input, size_t input_len, const char **pline_start, size_t *pline_len, size_t *padvance)
{
    size_t advance = 0;
    while (input_len > 0)
    {
        // skip blanks at the start
        size_t start;
        for (start = 0; start < input_len; start++)
        {
            char c = input[start];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != '_')
            {
                break;
            }
        }
        input += start;
        input_len -= start;
        advance += start;

        // look for the end of the line or start of comment
        size_t llen;
        for (llen = 0; llen < input_len; llen++)
        {
            char c = input[llen];
            if (c == '#' || c == '\n' || c == '\r')
                break;
        }

        // advance until the end of the line if there is a comment
        size_t ladvance = llen;
        if (llen < input_len && input[llen] == '#')
        {
            for (; ladvance < input_len; ladvance++)
            {
                char c = input[ladvance];
                if (c == '\n' || c == '\r')
                    break;
            }
        }

        // advance until there is no more whitespace
        for (; ladvance < input_len; ladvance++)
        {
            char c = input[ladvance];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
                break;
        }
        advance += ladvance;

        if (start == llen)
        {
            // the line is only comments or whitespace
            input += ladvance;
            input_len -= ladvance;
            continue;
        }
        else
        {
            // the line contains stuff
            *pline_start = input;
            *pline_len = llen;
            *padvance = advance;
            return true;
        }
    }

    // we reached the end of the
    // file without encountering more lines.
    *padvance = advance;
    return false;
}

static void print_serach_paths()
{
    fprintf(stderr, "Could not read source files (looking for test.S and test.bin)\n");
    fprintf(stderr, "Locations searched:\n");

    for (int i = 0; i < sizeof(locations) / sizeof(locations[0]); i++)
    {
        const char *loc = locations[i];
        if (!loc)
        {
            loc = "./";
        }
        fprintf(stderr, "  %s\n", locations[i]);
    }
}

int main()
{
    // load source files
    size_t source_len;
    const char *source = (const char *)try_read_file_multiple("test.S", &source_len);
    size_t binary_len;
    const uint8_t *binary = try_read_file_multiple("test.bin", &binary_len);

    if (!source || !binary)
    {
        print_serach_paths();
        return -1;
    }

    // initialize capstone
    csh handle;
    cs_err err = cs_open(CS_ARCH_XTENSA, CS_MODE_LITTLE_ENDIAN, &handle);
    if (err)
    {
        fprintf(stderr, "Could not initialize capstone. Error: %d\n", err);
        return -1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    // run through the files
    bool more_lines;
    bool more_binary;
    uint64_t address;
    int errors = 0;
    char dline[64];
    char sline[64];
    char *skipuntil = NULL;
    do
    {
        do
        {
            // step source
            const char *tmp;
            size_t llen;
            size_t ladvance;
            more_lines = next_line(
                source,
                source_len,
                &tmp,
                &llen,
                &ladvance);
            if (more_lines)
            {
                memcpy(sline, tmp, llen < 63 ? llen : 63);
                sline[llen < 63 ? llen : 63] = 0;
            }
            else
            {
                sline[0] = 0;
            }
            source += ladvance;
            source_len -= ladvance;

            if (skipuntil >= source)
            {
                printf("❌ <nothing> != %s\n", sline);
            }
        } while (skipuntil >= source);

        // step disassembly
        bool skippingdata;
        cs_insn *insn;
        size_t badvance;
        do
        {
            size_t ninsn = cs_disasm(
                handle,
                binary,
                binary_len,
                address,
                1, // only diassemble one instruction
                &insn);
            more_binary = ninsn != 0;
            if (more_binary)
            {
                snprintf(dline, sizeof(dline), "%s\t%s", insn->mnemonic, insn->op_str);
            }
            else
            {
                dline[0] = 0;
            }
            badvance = ninsn ? insn->size : 0;
            binary += badvance;
            binary_len -= badvance;
            skippingdata = more_binary && insn->id == XTENSA_INSN_INVALID;

            if (skippingdata)
            {
                printf("❌ %s\n", dline);
            }
        } while (skippingdata);

        if (more_lines && more_binary)
        {
            // check that the lines match
            bool match = strcmp(dline, sline) == 0;

            if (match)
            {
                printf("✔️ %s\n", dline);
            }
            else
            {
                // the line didnt' match, but the disassembly
                // may be ahead of the source now. So we need
                // to search and see if the instruction matcheds
                // down the line
                skipuntil = strstr(source, dline);

                if (skipuntil)
                {
                    binary -= badvance;
                    binary_len += badvance;
                    printf("❌ <nothing> != %s\n", sline);
                }
                else
                {
                    printf("❌ %s != %s\n", dline, sline);
                }
            }
        }
        else if (more_lines != more_binary)
        {
            errors++;
        }
    } while (more_lines && more_binary);

    cs_close(&handle);

    return errors;
}