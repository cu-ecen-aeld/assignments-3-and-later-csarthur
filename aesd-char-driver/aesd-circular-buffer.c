/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    int i = buffer->out_offs;
    int start = i;

    while (buffer->entry[i].buffptr && ((buffer->entry[i].size - 1) < char_offset))
    {                
        // The requested position is past the string pointed to by out_offs,
        // so decrement the size of the current entry and increment the index
        char_offset -= buffer->entry[i].size;
        i++;
        // Wrap if necessary        
        if (i == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
        {
            i = 0;
        }
        // We iterated over the entire buffer, and the requested position is past the end
        if (i == start)
        {
            return NULL;
        }
    }
    if (buffer->entry[i].buffptr)
    {        
        *entry_offset_byte_rtn = char_offset;
        return &(buffer->entry[i]);        
    }
    else
    {
        // The offset is past all of the valid entries
        return NULL;
    }
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    struct aesd_buffer_entry aesd_buffer_entry_copy = *add_entry;   
    buffer->entry[buffer->in_offs] = aesd_buffer_entry_copy;

    // Increment, wrapping if necessary
    buffer->in_offs = (buffer->in_offs == (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)) ? 0 : (buffer->in_offs + 1);

    if (!buffer->full)
    {
        // If buffer wasn't full prior to this add, but now it is, set flag
        // Next write will overwrite
        if (buffer->in_offs == buffer->out_offs)
        {
            //printf("Buffer is now full!!!!!!\r\n");
            buffer->full = true;
        }        
    }
    else // buffer was already full; advance output pointer ("overwite")
    {
        buffer->out_offs = buffer->in_offs;
    }        
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));    
}
