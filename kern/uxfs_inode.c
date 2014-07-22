/*--------------------------------------------------------------*/
/*--------------------------- uxfs_inode.c -----------------------*/
/*--------------------------------------------------------------*/

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/statfs.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/syscalls.h>
#include <linux/kdev_t.h>
#include "uxfs.h"

MODULE_AUTHOR
("Steve Pate <spate@veritas.com>, Wilson Felipe <wfelipe@gmail.com>");
MODULE_DESCRIPTION("A primitive filesystem for Linux");
MODULE_LICENSE("GPL");

void printInode(struct inode*, char *);
void printInode(struct inode *inode, char *method){
  if(!inode){
    printk("qqq !inode\n");
    printk("qqq null inode in method %s", method);
    for(;;){}
    return;
  }
  printk("qqq method called from: %s\n", method);
  printk("qqq pointer: %p\n", inode);
  printk("qqq private pointer: %p\n", inode->i_private);
  printk("qqq inode number: %lu\n", inode->i_ino);
  printk("qqq access permissions: %u\n", inode->i_mode);
  if(inode->i_mapping){
    printk("qqq address mapping host inode ptr: %p\n",inode->i_mapping->host);
    printk("qqq address mapping number of pages: %lu\n",inode->i_mapping->nrpages);
    printk("qqq address mapp`ing writeback page offset: %lu\n",inode->i_mapping->writeback_index);
  }
  printk("qqq inode owner user id: %u\n",inode->i_uid);
  printk("qqq inode owner group id: %u\n",inode->i_gid);
  printk("qqq filesize (bytes): %lld\n",inode->i_size);
  printk("qqq number of blocks: %lu\n",inode->i_blocks);
  printk("qqq block size (bits) %u\n",inode->i_blkbits);
  //  if(inode->i_atime)
    printk("qqq last access time: %ld3\n",inode->i_atime.tv_sec);
    //  if(inode->i_mtime)
    printk("qqq last modified time: %ld\n",inode->i_mtime.tv_sec);
    //  if(inode->i_ctime)
    printk("qqq list changed time: %ld\n",inode->i_ctime.tv_sec);
}

void printUip(struct uxfs_inode *, char *);
void printUip(struct uxfs_inode *uip, char *method){
  printk("method called from: %s\n", method);
  printk("pointer: %p\n", uip);
  printk("uip.i_mode: %u\n", uip->i_mode);
  printk("uip.i_nlink: %u\n", uip->i_nlink);
  printk("uip.i_atime: %u\n", uip->i_atime);
  printk("uip.i_mtime: %u\n", uip->i_mtime);
  printk("uip.i_ctime: %u\n", uip->i_ctime);
  printk("uip.i_uid: %u\n", uip->i_uid);
  printk("uip.i_gid: %u\n", uip->i_gid);
  printk("uip.i_size: %u\n", uip->i_size);
  printk("uip.i_blocks: %u\n", uip->i_blocks);
  printk("uip.i_addr[0]: %u\n", uip->i_addr[0]);
}



long testMethod(long,void *, long);
long testMethod(long number, void *p, long b){
  return number + b;
}

long *testPoinTer;
long *testPoinTer2;

/*
 * This function looks for "name" in the directory "dip". 
 * If found the inode number is returned.
 */

int uxfs_find_entry(struct inode *dip, char *name)
{

  
        long testNumber = 0xbeef00000000;
	struct uxfs_inode_info *uxi = uxfs_i(dip);
	struct super_block *sb = dip->i_sb;
	struct buffer_head *bh = NULL;
	struct uxfs_dirent *dirent;
	int i, blk = 0;
	long testNumber2 = 0xbad0000000000000;  
	testPoinTer = &testNumber;
	testPoinTer2 = &testNumber2;
	
  printk("name %s\n", name);
  printk("uxi->uip.i_blocks: %d\n", uxi->uip.i_blocks);
  printk("uxfs_find_entry(vfs_inode: %p)\n", dip);
	testNumber2 = testMethod(testNumber2, testPoinTer, (long) uxi->uip.i_blocks); 
	printUip(&uxi->uip, "uxfs_find_entry: dip");

	for (blk = 0; blk < uxi->uip.i_blocks; blk++) {
	  testNumber = 0xbead000000000000 + (long)uxi->uip.i_addr[blk] + ((long)blk*0x1000000000l);
	  for (;;){}
	  bh = sb_bread(sb, uxi->uip.i_addr[blk]);
	  //  testNumber= 	  testMethod(testNumber, &bh, 0x100);		
	  dirent = (struct uxfs_dirent *)bh->b_data;
	  //testNumber=testMethod(testNumber, &dirent, 0x1);
	  for (i = 0; i < UXFS_DIRS_PER_BLOCK; i++) {
	    if (strcmp(dirent->d_name, name) == 0) {
	      //  testNumber2=testMethod(testNumber2, &testNumber2, 0x1);
	      brelse(bh);
	      return dirent->d_ino;
	    }
	    dirent++;
	  }
	}
	if (bh)
	  brelse(bh);
	
	return 0;
}

/*
 * This function is called in response to an uxfs_iget(). For 
 * example, we call uxfs_iget() from uxfs_lookup().
 */

struct inode *uxfs_iget(struct super_block *sb, unsigned long ino)
{
	struct buffer_head *bh;
	struct uxfs_inode *di;
	struct inode *inode;
	int block;
	char *method;

	inode = iget_locked(sb, ino);
	
	method = "uxfs_iget before new check"; //debugging
	printInode(inode,method); //debugging
	if (!inode)
		return ERR_PTR(-ENOMEM);
	printk("abount to check I_NEW\n");
	if (!(inode->i_state & I_NEW))
		return inode;
	printk("inode was I_NEW\n");
	if (ino < UXFS_ROOT_INO || ino > UXFS_MAXFILES) {
		printk(KERN_ERR "uxfs: Bad inode number %lu\n", ino);
		return ERR_PTR(-EIO);
	}

	/*
	 * Note that for simplicity, there is only one 
	 * inode per block!
	 */

	block = UXFS_INODE_BLOCK + ino;
	bh = sb_bread(inode->i_sb, block);
	if (!bh) {
		printk(KERN_ERR "Unable to read inode %lu\n", ino);
		return ERR_PTR(-EIO);
	}

	di = (struct uxfs_inode *)(bh->b_data);
	inode->i_mode = di->i_mode;
	if (di->i_mode & S_IFDIR) {
		inode->i_mode |= S_IFDIR;
		inode->i_op = &uxfs_dir_inops;
		inode->i_fop = &uxfs_dir_operations;
	} else if (di->i_mode & S_IFREG) {
		inode->i_mode |= S_IFREG;
		inode->i_op = &uxfs_file_inops;
		inode->i_fop = &uxfs_file_operations;
		inode->i_mapping->a_ops = &uxfs_aops;
	}
	inode->i_uid = di->i_uid;
	inode->i_gid = di->i_gid;
	set_nlink(inode, di->i_nlink);
	inode->i_size = di->i_size;
	inode->i_blocks = di->i_blocks;
	inode->i_blkbits = UXFS_BSIZE;
	inode->i_atime.tv_sec = di->i_atime;
	inode->i_mtime.tv_sec = di->i_mtime;
	inode->i_ctime.tv_sec = di->i_ctime;
	memcpy(inode->i_private, di, sizeof(struct uxfs_inode));
	//testing!!!!! if the other thing doesnt work
	//	memcpy(uxfs_i(inode), di, sizeof(struct uxfs_inode));

	brelse(bh);

	unlock_new_inode(inode);
	printInode(inode, "uxfs_iget after new and getting set");
	return inode;
}

/*
 * This function is called to write a dirty inode to disk.
 */

int uxfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	unsigned long ino = inode->i_ino;
	struct uxfs_inode_info *uxi = uxfs_i(inode);
	struct buffer_head *bh;
	__u32 blk;

	if (ino < UXFS_ROOT_INO || ino > UXFS_MAXFILES) {
		printk(KERN_ERR "uxfs: Bad inode number %lu\n", ino);
		return -EIO;
	}
	blk = UXFS_INODE_BLOCK + ino;
	bh = sb_bread(inode->i_sb, blk);
	uxi->uip.i_mode = inode->i_mode;
	uxi->uip.i_nlink = inode->i_nlink;
	uxi->uip.i_atime = inode->i_atime.tv_sec;
	uxi->uip.i_mtime = inode->i_mtime.tv_sec;
	uxi->uip.i_ctime = inode->i_ctime.tv_sec;
	uxi->uip.i_uid = inode->i_uid;
	uxi->uip.i_gid = inode->i_gid;
	uxi->uip.i_size = inode->i_size;
	memcpy(bh->b_data, &uxi->uip, sizeof(struct uxfs_inode));
	mark_buffer_dirty(bh);
	brelse(bh);

	return 0;
}

/*
 * This function gets called when the link count goes to zero.
 */

void uxfs_destroy_inode(struct inode *inode)
{
	unsigned long inum = inode->i_ino;
	struct uxfs_inode_info *uxi = uxfs_i(inode);
	struct super_block *sb = inode->i_sb;
	struct uxfs_fs *fs = (struct uxfs_fs *)sb->s_fs_info;
	struct uxfs_superblock *usb = fs->u_sb;
	int i;

	usb->s_nbfree += uxi->uip.i_blocks;
	for (i = 0; i < uxi->uip.i_blocks; i++) {
		usb->s_block[uxi->uip.i_addr[i]] = UXFS_BLOCK_FREE;
		uxi->uip.i_addr[i] = UXFS_BLOCK_FREE;
	}
	usb->s_inode[inum] = UXFS_INODE_FREE;
	usb->s_nifree++;
	sb->s_dirt = 1;
	//clear_inode(inode);
}

/*
 * This function is called when the filesystem is being 
 * unmounted. We free the uxfs_fs structure allocated during 
 * uxfs_get_sb() and free the superblock buffer_head.
 */

void uxfs_put_super(struct super_block *s)
{
	struct uxfs_fs *fs = (struct uxfs_fs *)s->s_fs_info;
	struct buffer_head *bh = fs->u_sbh;

	/*
	 * Free the uxfs_fs structure allocated by uxfs_get_sb
	 */

	kfree(fs);
	brelse(bh);
}

/*
 * This function will be called by the df command.
 */

int uxfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct uxfs_fs *fs = (struct uxfs_fs *)sb->s_fs_info;
	struct uxfs_superblock *usb = fs->u_sb;

	buf->f_type = UXFS_MAGIC;
	buf->f_bsize = UXFS_BSIZE;
	buf->f_blocks = UXFS_MAXBLOCKS;
	buf->f_bfree = usb->s_nbfree;
	buf->f_bavail = usb->s_nbfree;
	buf->f_files = UXFS_MAXFILES;
	buf->f_ffree = usb->s_nifree;
	buf->f_fsid.val[0] = sb->s_dev;
	buf->f_namelen = UXFS_NAMELEN;

	return 0;
}

/*
 * This function is called to write the superblock to disk. We
 * simply mark it dirty and then set the s_dirt field of the
 * in-core superblock to 0 to prevent further unnecessary calls.
 */

void uxfs_write_super(struct super_block *sb)
{
	struct uxfs_fs *fs = (struct uxfs_fs *)sb->s_fs_info;
	struct buffer_head *bh = fs->u_sbh;

	if (!(sb->s_flags & MS_RDONLY))
		mark_buffer_dirty(bh);
	sb->s_dirt = 0;
}

static struct kmem_cache *uxfs_inode_cachep;

struct inode *uxfs_alloc_inode(struct super_block *sb)
{
	struct uxfs_inode_info *ui;

	ui = (struct uxfs_inode_info *) kmem_cache_alloc(uxfs_inode_cachep, GFP_KERNEL);
	//set vfs_inode private
	ui->vfs_inode.i_private = &ui;

	printk("vfs_inode allocated at: %p\n" , &ui->vfs_inode);
	printk("uxfs/vfs_inode initial i_blocks: %d, %lu\n", ui->uip.i_blocks , ui->vfs_inode.i_blocks ); 
	printInode(&ui->vfs_inode, "uxfs_alloc_inode"); //debugging
	return &ui->vfs_inode;
}

struct super_operations uxfs_sops = {
	.write_inode = uxfs_write_inode,
	.destroy_inode = uxfs_destroy_inode,
	.put_super = uxfs_put_super,
	.write_super = uxfs_write_super,
	.statfs = uxfs_statfs,
	.alloc_inode = uxfs_alloc_inode,
};

int uxfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct uxfs_superblock *usb;
	struct uxfs_fs *fs;
	struct buffer_head *bh;
	struct inode *inode;

	sb_set_blocksize(sb, (sizeof(struct uxfs_superblock)/512 + 1) * UXFS_BSIZE);
	bh = sb_bread(sb, 0);
	if (!bh)
		return -ENOMEM;

	sb_set_blocksize(sb, UXFS_BSIZE);
	sb->s_blocksize = UXFS_BSIZE;
	sb->s_blocksize_bits = UXFS_BSIZE_BITS;

	usb = (struct uxfs_superblock *)bh->b_data;
	if (usb->s_magic != UXFS_MAGIC) {
		if (!silent)
			printk(KERN_ERR "Unable to find uxfs filesystem\n");
		return -EINVAL;
	}
	if (usb->s_mod == UXFS_FSDIRTY) {
		printk(KERN_ERR "Filesystem is not clean. Write and "
		       "run fsck!\n");
		return -ENOMEM;
	}

	/*
	 *  We should really mark the superblock to
	 *  be dirty and write it back to disk.
	 */

	fs = kzalloc(sizeof(struct uxfs_fs), GFP_KERNEL);
	fs->u_sb = usb;
	fs->u_sbh = bh;
	sb->s_fs_info = fs;

	sb->s_magic = UXFS_MAGIC;
	sb->s_op = &uxfs_sops;

	inode = uxfs_iget(sb, UXFS_ROOT_INO);
	if (!inode)
		return -ENOMEM;
	printInode(inode, "uxfs_fill_super"); //debugging
	sb->s_root = d_alloc_root(inode); //changed from d_make_root(inode) for kernel version 3.2
	if (!sb->s_root) {
		iput(inode);
		return -EINVAL;
	}

	if (!(sb->s_flags & MS_RDONLY)) {
		mark_buffer_dirty(bh);
		sb->s_dirt = 1;
	}
	return 0;
}

static struct dentry *uxfs_mount(struct file_system_type *fs_type,
			       int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, uxfs_fill_super);
}

static struct file_system_type uxfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "uxfs",
	.mount = uxfs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};

static void init_once(void *foo)
{
	struct uxfs_inode_info *ei = (struct uxfs_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init init_uxfs_fs(void)
{
	uxfs_inode_cachep = kmem_cache_create("uxfs_inode_cache",
					      sizeof(struct uxfs_inode_info),
					      0, (SLAB_RECLAIM_ACCOUNT|
						  SLAB_MEM_SPREAD),
					      init_once);
	return register_filesystem(&uxfs_fs_type);
}

static void __exit exit_uxfs_fs(void)
{
	unregister_filesystem(&uxfs_fs_type);
}

module_init(init_uxfs_fs)
module_exit(exit_uxfs_fs)
