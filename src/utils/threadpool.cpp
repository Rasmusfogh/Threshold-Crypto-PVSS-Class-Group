#include "threadpool.hpp"

ThreadPool* ThreadPool::instance_ { nullptr };
std::mutex ThreadPool::instance_mutex_;