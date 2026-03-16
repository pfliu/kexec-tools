#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pe.h>
#include "kexec.h"
#include "arch/options.h"



int bpf_image_probe(const char *file_buf, off_t buf_sz)
{
	struct pe_hdr *pe_hdr;
	struct pe32plus_opt_hdr *opt_hdr;
	struct section_header *sect_hdr;
	int pe_hdr_offset, section_nr, linux_sz = -1;
	char *pe_part_buf, *linux_src;

	/* Check the validity of a PE */
	pe_hdr_offset = get_pehdr_offset(file_buf);
	pe_part_buf = (char *)file_buf + pe_hdr_offset;
	pe_hdr = (struct pe_hdr *)pe_part_buf;
	if (pe_hdr->opt_hdr_size == 0) {
		printf("ERR: optional header is missing\n");
		return -1;
	}
	section_nr = pe_hdr->sections;
	opt_hdr = (struct pe32plus_opt_hdr *)(pe_part_buf + sizeof(struct pe_hdr));
	sect_hdr = (struct section_header *)((char *)opt_hdr + pe_hdr->opt_hdr_size);
	return 0;
}

// tmp for arm64
int bpf_image_load(int argc, char **argv, const char *buf, off_t len,
			struct kexec_info *info)
{
	int result = -1;

	/* This load method does not fill info->kernel_fd */

	if (info->file_mode) {
		//tmp
		if (arm64_opts.initrd) {
			info->initrd_fd = open(arm64_opts.initrd, O_RDONLY);
			if (info->initrd_fd == -1) {
				fprintf(stderr,
					"Could not open initrd file %s:%s\n",
					arm64_opts.initrd, strerror(errno));
				result = EFAILED;
				goto exit;
			}
		}

		//tmp
		if (arm64_opts.command_line) {
			info->command_line = (char *)arm64_opts.command_line;
			info->command_line_len =
					strlen(arm64_opts.command_line) + 1;
		}

		return 0;
	}

	/* Only support kexec_file_load */
exit:
	fprintf(stderr, "kexec: load failed.\n");
        return result;
}
void bpf_image_usage(void)
{
	printf(
"     A PE image.\n");
}
