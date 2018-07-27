//
//  main.m
//  zlipo
//
//  Created by yanguo sun on 2018/7/27.
//  Copyright © 2018 Lvmama. All rights reserved.
//
#include <mach/machine.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <libc.h>
#include <utime.h>
#include <stdbool.h>
#include <stdint.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/swap.h>
#include <string.h>

#define MAXSECTALIGN        15 /* 2**15 or 0x8000 */
#define    SARMAG        8        /* strlen(ARMAG); */
#define    ARMAG        "!<arch>\n"    /* ar "magic number" */

#define SWAP_INT(a)  ( ((a) << 24) | \
(((a) << 8) & 0x00ff0000) | \
(((a) >> 8) & 0x0000ff00) | \
((unsigned int)(a) >> 24) )

enum byte_sex {
    UNKNOWN_BYTE_SEX,
    BIG_ENDIAN_BYTE_SEX,
    LITTLE_ENDIAN_BYTE_SEX
};

void swap_fat_header( struct fat_header *fat_header, enum NXByteOrder target_byte_sex) {
    fat_header->magic     = OSSwapInt32(fat_header->magic);
    fat_header->nfat_arch = OSSwapInt32(fat_header->nfat_arch);
}

void swap_fat_arch( struct fat_arch *fat_archs, uint32_t nfat_arch, enum NXByteOrder target_byte_sex) {
    uint32_t i;

    for(i = 0; i < nfat_arch; i++){
        fat_archs[i].cputype    = OSSwapInt32(fat_archs[i].cputype);
        fat_archs[i].cpusubtype = OSSwapInt32(fat_archs[i].cpusubtype);
        fat_archs[i].offset     = OSSwapInt32(fat_archs[i].offset);
        fat_archs[i].size       = OSSwapInt32(fat_archs[i].size);
        fat_archs[i].align      = OSSwapInt32(fat_archs[i].align);
    }
}

void swap_mach_header_64( struct mach_header_64 *mh, enum NXByteOrder target_byte_sex) {
    mh->magic = OSSwapInt32(mh->magic);
    mh->cputype = OSSwapInt32(mh->cputype);
    mh->cpusubtype = OSSwapInt32(mh->cpusubtype);
    mh->filetype = OSSwapInt32(mh->filetype);
    mh->ncmds = OSSwapInt32(mh->ncmds);
    mh->sizeofcmds = OSSwapInt32(mh->sizeofcmds);
    mh->flags = OSSwapInt32(mh->flags);
    mh->reserved = OSSwapInt32(mh->reserved);
}



enum byte_sex get_host_byte_sex(void) {
    uint32_t s;
    s = (BIG_ENDIAN_BYTE_SEX << 24) | LITTLE_ENDIAN_BYTE_SEX;
    return((enum byte_sex)*((char *)&s));
}

static char archives_in_input = false;

struct thin_file {
    char *name;
    char *addr;
    struct fat_arch fat_arch;
    char from_fat;
    char extract;
    char remove;
    char replace;
};

struct arch_flag {
    char *name;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
};

/* names and types (if any) of input file specified on the commmand line */
struct input_file {
    char *name;
    struct arch_flag arch_flag;
    struct fat_header *fat_header;
    struct fat_arch *fat_arches;
    char is_thin;
};
static uint32_t output_filemode = 0;
static struct utimbuf output_timep = { 0 };

void *reallocate(void *,size_t size);
void * allocate( size_t size) {
    void *p;

    if(size == 0)
        return(NULL);
    if((p = malloc(size)) == NULL)
        printf("failed");
    return(p);
}

void * reallocate( void *p, size_t size) {
    if(p == NULL)
        return(allocate(size));
    if((p = realloc(p, size)) == NULL)
        printf("failed");
    return(p);
}

static struct input_file *input_files = NULL;
static uint32_t ninput_files = 0;
static struct input_file *new_input(void);
static
struct input_file * new_input(void) {
    struct input_file *input;

    input_files = reallocate(input_files,
                             (ninput_files + 1) * sizeof(struct input_file));
    input = input_files + ninput_files;
    ninput_files++;
    memset(input, '\0', sizeof(struct input_file));
    return(input);
}
static struct thin_file *thin_files = NULL;
static uint32_t nthin_files = 0;
static struct thin_file * new_thin(void) {
    struct thin_file *thin;

    thin_files = reallocate(thin_files,
                            (nthin_files + 1) * sizeof(struct thin_file));
    thin = thin_files + nthin_files;
    nthin_files++;
    memset(thin, '\0', sizeof(struct thin_file));
    return(thin);
}

static void process_input_file(struct input_file *input) {
    int fd;
    struct stat stat_buf, stat_buf2;
    uint32_t size, i, j;
    char *addr;
    struct thin_file *thin;
    struct mach_header *mhp, mh;
    struct mach_header_64 *mhp64, mh64;
    struct load_command *lcp;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    char swapped;
    uint64_t big_size;
    /* Open the input file and map it in */
    if((fd = open(input->name, O_RDONLY)) == -1)
         printf("1");
    if(fstat(fd, &stat_buf) == -1)
         printf("1");
    size = (uint32_t)stat_buf.st_size;
    /* pick up set uid, set gid and sticky text bits */
    output_filemode = stat_buf.st_mode & 07777;
    /*
     * Select the eariliest modify time so that if the output file
     * contains archives with table of contents lipo will not make them
     * out of date.  This logic however could make an out of date table of
     * contents appear up todate if another file is combined with it that
     * has a date early enough.
     */
#ifndef __OPENSTEP__
    if(output_timep.modtime == 0 ||
       output_timep.modtime > stat_buf.st_mtime){
        output_timep.actime = stat_buf.st_atime;
        output_timep.modtime = stat_buf.st_mtime;
    }
#endif
    /*
     * mmap() can't handle mapping regular files with zero size.  So this
     * is handled separately.
     */
    if((stat_buf.st_mode & S_IFREG) == S_IFREG && size == 0) {
        addr = NULL;
    } else {
        addr = mmap(0, size, PROT_READ|PROT_WRITE, MAP_FILE|MAP_PRIVATE, fd, 0);
    }
    close(fd);

    /* Try to figure out what kind of file this is */

    /* see if this file is a fat file */
    if(size >= sizeof(struct fat_header) &&
#ifdef __BIG_ENDIAN__
       *((uint32_t *)addr) == FAT_MAGIC)
#endif /* __BIG_ENDIAN__ */
#ifdef __LITTLE_ENDIAN__
        *((uint32_t *)addr) == SWAP_INT(FAT_MAGIC))
#endif /* __LITTLE_ENDIAN__ */
    {

        input->fat_header = (struct fat_header *)addr;
#ifdef __LITTLE_ENDIAN__
        swap_fat_header(input->fat_header, 1);
#endif /* __LITTLE_ENDIAN__ */
        big_size = input->fat_header->nfat_arch;
        big_size *= sizeof(struct fat_arch);
        big_size += sizeof(struct fat_header);

        input->fat_arches = (struct fat_arch *)(addr + sizeof(struct fat_header));
#ifdef __LITTLE_ENDIAN__
        swap_fat_arch(input->fat_arches, input->fat_header->nfat_arch, (enum NXByteOrder)LITTLE_ENDIAN_BYTE_SEX);
#endif /* __LITTLE_ENDIAN__ */
        for(i = 0; i < input->fat_header->nfat_arch; i++){
            if(input->fat_arches[i].offset + input->fat_arches[i].size > size)
                printf("1");
            if(input->fat_arches[i].align > MAXSECTALIGN)
                printf("1");
            if(input->fat_arches[i].offset % (1 << input->fat_arches[i].align) != 0)
                printf("1");
        }
        /* create a thin file struct for each arch in the fat file */
        for(i = 0; i < input->fat_header->nfat_arch; i++){
            thin = new_thin();
            thin->name = input->name;
            thin->addr = addr + input->fat_arches[i].offset;
            thin->fat_arch = input->fat_arches[i];
            thin->from_fat = TRUE;
            if(input->fat_arches[i].size >= SARMAG && strncmp(thin->addr, ARMAG, SARMAG) == 0)
                archives_in_input = TRUE;
        }

    }
    /* see if this file is Mach-O file for 32-bit architectures */
    else if(size >= sizeof(struct mach_header) &&
            (*((uint32_t *)addr) == MH_MAGIC ||
             *((uint32_t *)addr) == SWAP_INT(MH_MAGIC))){

                /* this is a Mach-O file so create a thin file struct for it */
                thin = new_thin();
                input->is_thin = TRUE;
                thin->name = input->name;
                thin->addr = addr;
                mhp = (struct mach_header *)addr;
                lcp = (struct load_command *)((char *)mhp +
                                              sizeof(struct mach_header));
                if(mhp->magic == SWAP_INT(MH_MAGIC)){
                    swapped = TRUE;
                    mh = *mhp;
//                    swap_mach_header(&mh, get_host_byte_sex());
                    mhp = &mh;
                } else {
                    swapped = FALSE;
                }

                thin->fat_arch.cputype = mhp->cputype;
                thin->fat_arch.cpusubtype = mhp->cpusubtype;
                thin->fat_arch.offset = 0;
                thin->fat_arch.size = size;
//                thin->fat_arch.align = get_align(mhp, lcp, size, input->name,
//                                                 swapped);

                /* if the arch type is specified make sure it matches the object */
//                if(input->arch_flag.name != NULL)
//                    check_arch(input, thin);
            }
    /* see if this file is Mach-O file for 64-bit architectures */
    else if(size >= sizeof(struct mach_header_64) &&
            (*((uint32_t *)addr) == MH_MAGIC_64 ||
             *((uint32_t *)addr) == SWAP_INT(MH_MAGIC_64))){

                /* this is a Mach-O file so create a thin file struct for it */
                thin = new_thin();
                input->is_thin = TRUE;
                thin->name = input->name;
                thin->addr = addr;
                mhp64 = (struct mach_header_64 *)addr;
                lcp = (struct load_command *)((char *)mhp64 +
                                              sizeof(struct mach_header_64));
                if(mhp64->magic == SWAP_INT(MH_MAGIC_64)){
                    swapped = TRUE;
                    mh64 = *mhp64;
                    swap_mach_header_64(&mh64, (enum NXByteOrder)get_host_byte_sex());
                    mhp64 = &mh64;
                }
                else
                    swapped = FALSE;
                thin->fat_arch.cputype = mhp64->cputype;
                thin->fat_arch.cpusubtype = mhp64->cpusubtype;
                thin->fat_arch.offset = 0;
                thin->fat_arch.size = size;
            }

}

static void print_arch(struct fat_arch *fat_arch) {
    switch(fat_arch->cputype){
        case CPU_TYPE_I386:
            switch(fat_arch->cpusubtype & ~CPU_SUBTYPE_MASK){
                case CPU_SUBTYPE_I386_ALL:
                    /* case CPU_SUBTYPE_386: same as above */
                    printf("i386");
                    break;
                case CPU_SUBTYPE_486:
                    printf("i486");
                    break;
                case CPU_SUBTYPE_486SX:
                    printf("i486SX");
                    break;
                case CPU_SUBTYPE_PENT: /* same as 586 */
                    printf("pentium");
                    break;
                case CPU_SUBTYPE_PENTPRO:
                    printf("pentpro");
                    break;
                case CPU_SUBTYPE_PENTII_M3:
                    printf("pentIIm3");
                    break;
                case CPU_SUBTYPE_PENTII_M5:
                    printf("pentIIm5");
                    break;
                default:
                    goto print_arch_unknown;
            }
            break;
        case CPU_TYPE_X86_64:
            switch(fat_arch->cpusubtype & ~CPU_SUBTYPE_MASK){
                case CPU_SUBTYPE_X86_64_ALL:
                    printf("x86_64");
                    break;
                case CPU_SUBTYPE_X86_64_H:
                    printf("x86_64h");
                    break;
                default:
                    goto print_arch_unknown;
            }
            break;
        case CPU_TYPE_I860:
            switch(fat_arch->cpusubtype & ~CPU_SUBTYPE_MASK){
                case CPU_SUBTYPE_I860_ALL:
                case CPU_SUBTYPE_I860_860:
                    printf("i860");
                    break;
                default:
                    goto print_arch_unknown;
            }
            break;
        case CPU_TYPE_HPPA:
            switch(fat_arch->cpusubtype & ~CPU_SUBTYPE_MASK){
                case CPU_SUBTYPE_HPPA_ALL:
                case CPU_SUBTYPE_HPPA_7100LC:
                    printf("hppa");
                    break;
                default:
                    goto print_arch_unknown;
            }
            break;
        case CPU_TYPE_SPARC:
            switch(fat_arch->cpusubtype & ~CPU_SUBTYPE_MASK){
                case CPU_SUBTYPE_SPARC_ALL:
                    printf("sparc");
                    break;
                default:
                    goto print_arch_unknown;
            }
            break;
        case CPU_TYPE_ARM:
            switch(fat_arch->cpusubtype){
                case CPU_SUBTYPE_ARM_ALL:
                    printf("arm");
                    break;
                case CPU_SUBTYPE_ARM_V4T:
                    printf("armv4t");
                    break;
                case CPU_SUBTYPE_ARM_V5TEJ:
                    printf("armv5");
                    break;
                case CPU_SUBTYPE_ARM_XSCALE:
                    printf("xscale");
                    break;
                case CPU_SUBTYPE_ARM_V6:
                    printf("armv6");
                    break;
                case CPU_SUBTYPE_ARM_V6M:
                    printf("armv6m");
                    break;
                case CPU_SUBTYPE_ARM_V7:
                    printf("armv7");
                    break;
                case CPU_SUBTYPE_ARM_V7F:
                    printf("armv7f");
                    break;
                case CPU_SUBTYPE_ARM_V7S:
                    printf("armv7s");
                    break;
                case CPU_SUBTYPE_ARM_V7K:
                    printf("armv7k");
                    break;
                case CPU_SUBTYPE_ARM_V7M:
                    printf("armv7m");
                    break;
                case CPU_SUBTYPE_ARM_V7EM:
                    printf("armv7em");
                    break;
                default:
                    goto print_arch_unknown;
            }
            break;
        case CPU_TYPE_ARM64:
            switch(fat_arch->cpusubtype & ~CPU_SUBTYPE_MASK){
                case CPU_SUBTYPE_ARM64_ALL:
                    printf("arm64");
                    break;
                case CPU_SUBTYPE_ARM64_V8:
                    printf("arm64v8");
                    break;
                default:
                    goto print_arch_unknown;
            }
            break;
        case CPU_TYPE_ANY:
            switch(fat_arch->cpusubtype & ~CPU_SUBTYPE_MASK){
                case CPU_SUBTYPE_MULTIPLE:
                    printf("any");
                    break;
                case CPU_SUBTYPE_LITTLE_ENDIAN:
                    printf("little");
                    break;
                case CPU_SUBTYPE_BIG_ENDIAN:
                    printf("big");
                    break;
                default:
                    goto print_arch_unknown;
            }
            break;
        print_arch_unknown:
        default:
            printf("(cputype (%d) cpusubtype (%d))", fat_arch->cputype,
                   fat_arch->cpusubtype & ~CPU_SUBTYPE_MASK);
            break;
    }
}

int main(int argc, const char * argv[]) {
    struct input_file *input;
    input = new_input();
    int i,a, j;
    bool aa = true;
//    for(a = 1; a < argc; a++){
//        printf("%s", argv[a]);
//    }

    input->name = (char *)argv[1];
//    printf("%s\n", input->name);
    for(i = 0; i < ninput_files; i++)
        process_input_file(input_files + i);


    for(i = 0; i < ninput_files; i++){
        if(input_files[i].fat_header != NULL){
//            printf("Fat header in: %s\n", input_files[i].name);
//            printf("fat_magic 0x%x\n",  (unsigned int)(input_files[i].fat_header->magic));
//            printf("nfat_arch %u\n", input_files[i].fat_header->nfat_arch);
            for(j = 0; j < input_files[i].fat_header->nfat_arch; j++){
                print_arch(&(input_files[i].fat_arches[j]));
                printf(" %u\n",
                       input_files[i].fat_arches[j].size);
            }

        }
    }
    return 0;
}
