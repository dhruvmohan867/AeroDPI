#pragma once
#include <vector>
#include <atomic>
#include <cstdint>
#include <stdexcept>

namespace DPI {

class MemoryPool {
public:
    static constexpr size_t SLOT_SIZE = 2048;

    MemoryPool(size_t slot_count)
        : pool(slot_count * SLOT_SIZE),
          free_stack(slot_count),
          top(slot_count)
    {
        for (size_t i = 0; i < slot_count; ++i)
            free_stack[i] = slot_count - 1 - i;
    }

    // Acquire slot
    uint8_t* acquire(size_t& index) {
        size_t old_top = top.fetch_sub(1, std::memory_order_acq_rel);
        if (old_top == 0) {
            top.fetch_add(1);
            return nullptr; // pool empty
        }
        index = free_stack[old_top - 1];
        return &pool[index * SLOT_SIZE];
    }

    // Release slot
    void release(size_t index) {
        size_t old_top = top.fetch_add(1, std::memory_order_acq_rel);
        free_stack[old_top] = index;
    }

private:
    std::vector<uint8_t> pool;
    std::vector<size_t> free_stack;
    std::atomic<size_t> top;
};

}