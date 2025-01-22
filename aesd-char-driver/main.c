/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/fs.h> // file_operations
#include <linux/string.h>
#include <linux/slab.h>
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Christopher Arthur");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev; /* device information */
    PDEBUG("open");
	dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	filp->private_data = dev; /* for other methods */
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    ssize_t num_of_available_bytes = 0;
    unsigned long bytes_not_copied;
    ssize_t offset_within_entry;
    struct aesd_circular_buffer * circ_buffer = ((struct aesd_dev *)(filp->private_data))->circ_buffer;
    struct aesd_buffer_entry * this_entry;
    char * output_buffer = (char *)kzalloc(count * sizeof(char), GFP_KERNEL);    

    if (!output_buffer)
    {
        printk(KERN_WARNING "Can't reallocate memory for read buffer: %lu bytes\n", count);
        return -ENOMEM;
    }    

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    
    this_entry = aesd_circular_buffer_find_entry_offset_for_fpos(circ_buffer, *f_pos, &offset_within_entry);
    if (!this_entry)    
    {
        kfree(output_buffer);
        return 0;
    }                
    num_of_available_bytes = this_entry->size - offset_within_entry;
    if (num_of_available_bytes > count)
    {
        strncpy(output_buffer, this_entry->buffptr + offset_within_entry, count);
        retval = count;            
        *f_pos += count;
    }
    else
    {
        strncpy(output_buffer, this_entry->buffptr + offset_within_entry, num_of_available_bytes);
        retval = num_of_available_bytes;
        *f_pos += num_of_available_bytes;
    }

    bytes_not_copied = copy_to_user(buf, output_buffer, retval);
    if (bytes_not_copied)
    {
        retval -= bytes_not_copied;
        printk(KERN_WARNING "Could not copy all data to user space:  %lu bytes\n", bytes_not_copied);
    }
    kfree(output_buffer);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_circular_buffer * circ_buffer = ((struct aesd_dev *)(filp->private_data))->circ_buffer;
    struct aesd_buffer_entry * new_entry = ((struct aesd_dev *)(filp->private_data))->working_entry;  
    char * new_entry_string;
    const char * contents_of_previous_write;
    char * temp_new_ptr;
    char * local_buf;
    char has_newline = 0; 
    int i = 0;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);    
    
    if (mutex_lock_interruptible(&(((struct aesd_dev *)(filp->private_data))->lock)))
    {
        printk(KERN_WARNING "Interrupted waiting on mutex lock");
        return -EINTR;
    }
    
    local_buf = (char *)kzalloc(count * sizeof(char), GFP_KERNEL);

    if (new_entry->buffptr == NULL)  
    {
        new_entry_string = (char *)(kzalloc(count * sizeof(char), GFP_KERNEL));
        if (!new_entry_string)
        {
            printk(KERN_WARNING "Can't allocate memory for string to write: %lu bytes\n", count);
            mutex_unlock(&(((struct aesd_dev *)(filp->private_data))->lock));
            return retval;
        }        
    }
    else 
    {
        contents_of_previous_write = new_entry->buffptr;
        // Handle the case where we got an incomplete entry (lacking newline) on a previous call    
        temp_new_ptr = (char *)(kzalloc(new_entry->size + (count * sizeof(char)), GFP_KERNEL));
        if (temp_new_ptr)
        {
            memcpy(temp_new_ptr, contents_of_previous_write, new_entry->size + count);
            kfree(contents_of_previous_write);
            new_entry_string = temp_new_ptr;
        }        
        else
        {
            printk(KERN_WARNING "Can't reallocate memory for string to write: %lu bytes\n", count);
            mutex_unlock(&(((struct aesd_dev *)(filp->private_data))->lock));
            return retval;
        }
    }

    retval = copy_from_user(local_buf, buf, count);
    if (retval)
    {
        printk(KERN_WARNING "Could not copy all user data passed to write(): %lu bytes not written\n", retval);
        count -= retval;
    }
    strncat(new_entry_string, local_buf, count);
    kfree(local_buf);
    new_entry->buffptr = new_entry_string;
    new_entry->size = count;
    for (i = 0; i < count; i++)
    {
        if (new_entry->buffptr[i] == '\n')
        {
            has_newline = 1;
        }
    }
    if (has_newline)
    {   
        // Check to see if buffer is full; if so, free the memory at the oldest location,
        // which is the location about to be written to
        if (circ_buffer->full)
        {
            kfree(circ_buffer->entry[circ_buffer->in_offs].buffptr);
        }
        aesd_circular_buffer_add_entry(circ_buffer, new_entry);
        new_entry->size = 0;
        new_entry->buffptr = NULL;
        mutex_unlock(&(((struct aesd_dev *)(filp->private_data))->lock));
        return count;
    }
    else
    {
        mutex_unlock(&(((struct aesd_dev *)(filp->private_data))->lock));
        return count;
    }
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    aesd_device.circ_buffer =
         (struct aesd_circular_buffer *)(kzalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL));
    if (!aesd_device.circ_buffer)
    {
        printk(KERN_WARNING "Can't allocate memory for circular buffer\n");
        unregister_chrdev_region(dev, 1);
        return -ENOMEM;
    }
    aesd_device.working_entry = (struct aesd_buffer_entry *)(kzalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL));
    if (!aesd_device.working_entry)
    {
        printk(KERN_WARNING "Can't allocate memory for working entry\n");
        unregister_chrdev_region(dev, 1);
        return -ENOMEM;
    }
    mutex_init(&(aesd_device.lock));

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);
        
    mutex_destroy(&(aesd_device.lock));
    
    if(aesd_device.circ_buffer)
    {
        kfree(aesd_device.circ_buffer);
    }
    if(aesd_device.working_entry)
    {
        kfree(aesd_device.working_entry);
    }
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
