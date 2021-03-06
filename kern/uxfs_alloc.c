/*--------------------------------------------------------------*/
/*--------------------------- uxfs_alloc.c -----------------------*/
/*--------------------------------------------------------------*/

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "uxfs.h"

/*
 * Allocate a new inode. We update the superblock and return
 * the inode number.
 */

ino_t uxfs_ialloc(struct super_block *sb)
{
	struct uxfs_fs *fs = (struct uxfs_fs *)sb->s_fs_info;
	struct uxfs_superblock *usb = fs->u_sb;
	int i;

	if (usb->s_nifree == 0) {
		printk(KERN_WARNING "uxfs: Out of inodes\n");
		return 0;
	}
	for (i = 3; i < UXFS_MAXFILES; i++) {
		if (usb->s_inode[i] == UXFS_INODE_FREE) {
			usb->s_inode[i] = UXFS_INODE_INUSE;
			usb->s_nifree--;
			sb->s_dirt = 1;
			return i;
		}
	}
	printk(KERN_ERR
	       "uxfs: uxfs_ialloc - We should never reach here\n");
	return 0;
}

/*
 * Allocate a new data block. We update the superblock and return
 * the new block  number.
 */

__u32 uxfs_block_alloc(struct super_block * sb)
{
	struct uxfs_fs *fs = (struct uxfs_fs *)sb->s_fs_info;
	struct uxfs_superblock *usb = fs->u_sb;
	int i;

	if (usb->s_nbfree == 0) {
		printk(KERN_WARNING "uxfs: Out of space\n");
		return 0;
	}

	/*
	 * Start looking at block 1. Block 0 is 
	 * for the root directory.
	 */

	for (i = 1; i < UXFS_MAXBLOCKS; i++) {
		if (usb->s_block[i] == UXFS_BLOCK_FREE) {
			usb->s_block[i] = UXFS_BLOCK_INUSE;
			usb->s_nbfree--;
			sb->s_dirt = 1;
			return UXFS_FIRST_DATA_BLOCK + i;
		}
	}
	printk(KERN_ERR "uxfs: uxfs_block_alloc - "
	       "We should never reach here\n");
	return 0;
}
