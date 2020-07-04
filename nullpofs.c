/*
 * Copyright (C) 2020 yoh2
 *
 * nullpo.ko is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licence as published by the
 * Free Software Foundation, version 2 of the License, or (at your option)
 * any later version.
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/file.h>

#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

#define NULLPOFS_SUPER_MAGIC 0x6e756c6c
#define BOGO_DIRENT_SIZE  20
#define MAX_MSG_BUF       PAGE_SIZE

struct nullpofs_file_info {
	size_t msg_buf_size;
	char *msg_buf;
};

static ssize_t nullpofs_read(
	struct file *file, char __user *buf,
	size_t count, loff_t *ppos)
{
	if (count > 0) {
		send_sig(SIGSEGV, current, 0);
		return -EIO;
	} else
		return 0;
}

static ssize_t nullpofs_write(
	struct file *file, const char __user *buf,
	size_t count, loff_t *ppos)
{
	if (count > 0) {
		send_sig(SIGSEGV, current, 0);
		return -EIO;
	} else
		return 0;
}

static int nullpofs_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int nullpofs_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static const struct file_operations nullpofs_file_operations = {
	.llseek  = no_seek_end_llseek,
	.read    = nullpofs_read,
	.write   = nullpofs_write,
	.open    = nullpofs_open,
	.release = nullpofs_release,
};

static int nullpofs_getattr(const struct path *path, struct kstat *stat, u32 request_mask,
			    unsigned int query_flags)
{
	struct inode *inode = d_backing_inode(path->dentry);
	generic_fillattr(inode, stat);
	stat->size = 1;
	return 0;
}

static int nullpofs_setattr(struct dentry *dentry, struct iattr *attr)
{
	return 0;
}

static const struct inode_operations nullpofs_inode_operations = {
	.getattr = nullpofs_getattr,
	.setattr = nullpofs_setattr,
};

static struct inode *nullpofs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode);

static int nullpofs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err = 0;
	struct inode *inode = nullpofs_get_inode(dir->i_sb, dir, mode);
	if(inode == NULL) {
		err = -ENOSPC;
		goto err_get_inode;
	}
	dir->i_size += BOGO_DIRENT_SIZE;
	dir->i_ctime = dir->i_mtime = current_time(dir);
	d_instantiate(dentry, inode);
	dget(dentry);
	return 0;

err_get_inode:
	return err;
}

static int nullpofs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	return nullpofs_mknod(dir, dentry, mode | S_IFREG);
}

static int nullpofs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);

	dir->i_size += BOGO_DIRENT_SIZE;
	inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(inode);
	inc_nlink(inode);
	ihold(inode);
	dget(dentry);
	d_instantiate(dentry, inode);
	return 0;
}

static int nullpofs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	dir->i_size -= BOGO_DIRENT_SIZE;
	inode->i_ctime = dir->i_ctime = dir->i_mtime = current_time(inode);
	drop_nlink(inode);
	dput(dentry);
	return 0;
}

static int nullpofs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err = nullpofs_mknod(dir, dentry, mode | S_IFDIR);
	if(err) {
		return err;
	}
	inc_nlink(dir);
	return 0;
}

static int nullpofs_rmdir(struct inode *dir, struct dentry *dentry)
{
	if (!simple_empty(dentry)) {
		return -ENOTEMPTY;
	}
	drop_nlink(d_inode(dentry));
	drop_nlink(dir);
	return nullpofs_unlink(dir, dentry);
}

static const struct inode_operations nullpofs_dir_inode_operations = {
	.create = nullpofs_create,
	.lookup = simple_lookup,
	.link   = nullpofs_link,
	.unlink = nullpofs_unlink,
	.mkdir  = nullpofs_mkdir,
	.rmdir  = nullpofs_rmdir,
};

struct nullpofs_sb_info {
	umode_t mode;
	kuid_t uid;
	kgid_t gid;
	unsigned long next_ino;
};

struct nullpofs_inode_info {
	struct inode vfs_inode;
};

static inline struct nullpofs_inode_info *NULLPOFS_I(struct inode *inode)
{
	return container_of(inode, struct nullpofs_inode_info, vfs_inode);
}

static inline struct nullpofs_sb_info *NULLPOFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static void nullpofs_init_inode(void *foo)
{
	struct nullpofs_inode_info *info = (struct nullpofs_inode_info *)foo;
	inode_init_once(&info->vfs_inode);
}

static struct kmem_cache *nullpofs_inode_cachep;

static int nullpofs_init_inodecache(void)
{
	nullpofs_inode_cachep = kmem_cache_create("nullpofs_inode_cache",
		sizeof(struct nullpofs_inode_info),
		0, SLAB_PANIC, nullpofs_init_inode);
	if(nullpofs_inode_cachep == NULL) {
		return -ENOMEM;
	}
	return 0;
}

static void nullpofs_destroy_inodecache(void)
{
	rcu_barrier();
	kmem_cache_destroy(nullpofs_inode_cachep);
}

static struct inode *nullpofs_alloc_inode(struct super_block *sb)
{
	return kmem_cache_alloc(nullpofs_inode_cachep, GFP_NOFS);
}

static void nullpofs_i_callback(struct rcu_head *head)
{
	struct inode *inode;
	inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(nullpofs_inode_cachep, NULLPOFS_I(inode));
}

static void nullpofs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, nullpofs_i_callback);
}

static void nullpofs_evict_inode(struct inode *inode)
{
	clear_inode(inode);
}

static void nullpofs_put_super(struct super_block *sb)
{
	struct nullpofs_sb_info *sbinfo = NULLPOFS_SB(sb);
	kfree(sbinfo);
	sb->s_fs_info = NULL;
}

static int nullpofs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	buf->f_type = NULLPOFS_SUPER_MAGIC;
	buf->f_bsize = PAGE_SIZE;
	buf->f_blocks = 0;
	buf->f_bavail = 0;
	buf->f_bfree = 0;
	buf->f_namelen = NAME_MAX;

	return 0;
}

static int nullpofs_remount(struct super_block *sb, int *flags, char *data)
{
	return 0;
}

static struct inode *nullpofs_get_inode(struct super_block *sb, const struct inode *dir, umode_t mode)
{
	int err = 0;
	struct nullpofs_sb_info *sbinfo = NULLPOFS_SB(sb);
	struct inode *inode;

	inode = new_inode(sb);
	if(inode == NULL) {
		err = -ENOMEM;
		goto err_new_inode;
	}

	inode->i_ino = sbinfo->next_ino++;
	inode_init_owner(inode, dir, mode);
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_generation = get_seconds();

	switch(mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &nullpofs_inode_operations;
		inode->i_fop = &nullpofs_file_operations;
		break;

	case S_IFDIR:
		inc_nlink(inode);
		inode->i_size = 2 * BOGO_DIRENT_SIZE;
		inode->i_op = &nullpofs_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		break;

	default:
		err = -EOPNOTSUPP;
		goto err_mode;
	}

	return inode;
err_mode:
	free_inode_nonrcu(inode);
err_new_inode:
	return ERR_PTR(err);
}

static const struct super_operations nullpofs_ops = {
	.alloc_inode    = nullpofs_alloc_inode,
	.destroy_inode  = nullpofs_destroy_inode,
	.evict_inode    = nullpofs_evict_inode,
	.drop_inode     = generic_drop_inode,
	.put_super      = nullpofs_put_super,
	.statfs         = nullpofs_statfs,
	.remount_fs     = nullpofs_remount,
};

static int nullpofs_fill_super(struct super_block *sb, void *data, int silent)
{
	int err = 0;
	struct nullpofs_sb_info *sbinfo;
	struct inode *inode;

	sbinfo = kzalloc(max((int)sizeof(struct nullpofs_sb_info), L1_CACHE_BYTES), GFP_KERNEL);
	if(sbinfo == NULL) {
		err = -ENOMEM;
		goto err_alloc_sbinfo;
	}

	sbinfo->mode = S_IRWXUGO;
	sbinfo->uid = current_fsuid();
	sbinfo->gid = current_fsgid();
	sbinfo->next_ino = 1;
	sb->s_fs_info = sbinfo;

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
	sb->s_magic = NULLPOFS_SUPER_MAGIC;
	sb->s_op = &nullpofs_ops;
	sb->s_time_gran = 1;

	inode = nullpofs_get_inode(sb, NULL, S_IFDIR | sbinfo->mode);
	if(IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto err_get_inode;
	}
	sb->s_root = d_make_root(inode);
	if (sb->s_root == NULL) {
		err = -ENOMEM;
		goto err_make_root;
	}

	return 0;

err_make_root:
	free_inode_nonrcu(inode);
err_get_inode:
	nullpofs_put_super(sb);
err_alloc_sbinfo:
	return err;
}

static struct dentry *nullpofs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, nullpofs_fill_super);
}

static struct file_system_type nullpofs_fs_type = {
	.owner    = THIS_MODULE,
	.name     = "nullpofs",
	.mount    = nullpofs_mount,
	.kill_sb  = kill_litter_super,
	.fs_flags = FS_USERNS_MOUNT,
};


static int __init nullpofs_init(void)
{
	int err = 0;

	if(nullpofs_inode_cachep) {
		return 0;
	}

	err = nullpofs_init_inodecache();
	if(err) {
		printk(KERN_ALERT "nullpofs: failed to allocate inode cache.\n");
		goto err_init_inodecache;
	}

	err = register_filesystem(&nullpofs_fs_type);
	if(err) {
		printk(KERN_ALERT "nullpofs: failed to register.\n");
		goto err_register_fs;
	}
	return 0;

err_register_fs:
	nullpofs_destroy_inodecache();
err_init_inodecache:
	return err;
}

static void __exit nullpofs_cleanup(void)
{
	unregister_filesystem(&nullpofs_fs_type);
	nullpofs_destroy_inodecache();
}

module_init(nullpofs_init);
module_exit(nullpofs_cleanup);
