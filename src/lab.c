#include "lab.h"
#include <errno.h>
#include <sys/mman.h>
#include <string.h>


  size_t btok(size_t bytes) {
    unsigned int count = 0;
    if (bytes != 1) { bytes--; }
    while (bytes > 0) { bytes >>= 1; count++; }
    return count;
  }

  struct avail *buddy_calc(struct buddy_pool *pool, struct avail *buddy) {
    size_t offset = (char *)buddy - (char *)pool->base;
    size_t buddy_offset = offset ^ (UINT64_C(1) << buddy->kval);  // XOR to calculate buddy
    return (struct avail *)((char *)pool->base + buddy_offset);
  }

  void *buddy_malloc(struct buddy_pool *pool, size_t size) {
    if (!pool || size == 0) {
        errno = ENOMEM;
        return NULL;
    }

    size_t kval = btok(size + sizeof(struct avail));
    if (kval < SMALLEST_K) { 
      kval = SMALLEST_K;
    }

    for (size_t i = kval; i <= pool->kval_m; i++) {
        if (pool->avail[i].next != &pool->avail[i]) {
            struct avail *block = pool->avail[i].next;

            // Remove block from free list
            block->prev->next = block->next;
            block->next->prev = block->prev;

            // Split larger blocks until we reach the size
            while (i > kval) {
                i--;
                struct avail *buddy = (struct avail *)((char *)block + (UINT64_C(1) << i));
                buddy->kval = i;
                buddy->tag = BLOCK_AVAIL;

                // Add buddy to free list
                buddy->next = pool->avail[i].next;
                buddy->prev = &pool->avail[i];
                pool->avail[i].next->prev = buddy;
                pool->avail[i].next = buddy;
            }

            block->tag = BLOCK_RESERVED;
            return (void *)((char *)block + sizeof(struct avail));
        }
    }

    // No good block
    errno = ENOMEM;
    return NULL;
  }

  void buddy_free(struct buddy_pool *pool, void *ptr) {
    if (!pool || !ptr) {
        return;
    }

    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));
    size_t k = block->kval;
    block->tag = BLOCK_AVAIL;

    while (k < pool->kval_m) {
        struct avail *buddy = buddy_calc(pool, block);

        // Step S1: Check if buddy is available and mergeable
        if (!buddy || buddy->tag != BLOCK_AVAIL || buddy->kval != k) {
            return; // not available or not the right size
        }

        // Step S2: Merge with buddy / Remove buddy from free list
        buddy->prev->next = buddy->next;
        buddy->next->prev = buddy->prev;

        // Merge blocks
        if (buddy < block) {
            block = buddy;
        }
        k++;
        block->kval = k;
    }

    // Step S3: Add the block to the free list
    block->next = pool->avail[k].next;
    block->prev = &pool->avail[k];
    pool->avail[k].next->prev = block;
    pool->avail[k].next = block;

    // clear the smaller free blocks
    for (size_t i = 0; i < block->kval; i++) {
        pool->avail[i].next = &pool->avail[i];
        pool->avail[i].prev = &pool->avail[i];
    }

  }

  void *buddy_realloc(struct buddy_pool *pool, void *ptr, size_t size) {    
    if (!pool) { 
      return NULL;
    }

    if (!ptr) { 
      return buddy_malloc(pool, size); // basically just do malloc
    }

    if (size == 0) {
        buddy_free(pool, ptr); // basically just free
        return NULL;
    }

    struct avail *block = (struct avail *)((char *)ptr - sizeof(struct avail));
    size_t old_size = (UINT64_C(1) << block->kval) - sizeof(struct avail);

    if (size <= old_size) {
        return ptr; // No need to reallocate
    }

    // Allocate new block and copy data
    void *new_ptr = buddy_malloc(pool, size);
    if (new_ptr) {
        memcpy(new_ptr, ptr, old_size);
        buddy_free(pool, ptr);
    } 
    return new_ptr; // couldn't reallocate just return
  }

  void buddy_init(struct buddy_pool *pool, size_t size) {
    if (size == 0) {
        size = UINT64_C(1) << DEFAULT_K;
    }

    pool->kval_m = btok(size);
    pool->numbytes = UINT64_C(1) << pool->kval_m; // 2^btok
    
    
    pool->base = mmap(NULL, pool->numbytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool->base == MAP_FAILED) {
        perror("buddy: could not allocate memory pool!");
    }

    for (unsigned int i = 0; i <= pool->kval_m; i++) {
        // make every one point to iself
        pool->avail[i].next = &pool->avail[i]; // points to itself empty circular list
        pool->avail[i].prev = &pool->avail[i];
        pool->avail[i].kval = i;
        pool->avail[i].tag = BLOCK_UNUSED;
    }

    struct avail *ptr = (struct avail *) pool->base;
    ptr->tag = BLOCK_AVAIL;
    ptr->kval = pool->kval_m;
    ptr->next = &pool->avail[pool->kval_m];
    ptr->prev = &pool->avail[pool->kval_m];

    pool->avail[pool->kval_m].next = ptr;
    pool->avail[pool->kval_m].prev = ptr;
  }

  
  void buddy_destroy(struct buddy_pool *pool) {
	  int status = munmap(pool->base, pool->numbytes);
	  if (status == -1) {
		  perror("buddy: destroy failed!");
	  }
    memset(pool, 0, sizeof(struct buddy_pool));
  }