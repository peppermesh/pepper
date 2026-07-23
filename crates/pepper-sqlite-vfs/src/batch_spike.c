/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Instrumented wrapper VFS for the SQLite batch-atomic feasibility gate.
 *
 * This is not Pepper's production storage VFS. It wraps the default SQLite
 * VFS, advertises SQLITE_IOCAP_BATCH_ATOMIC, buffers writes between the
 * documented file-control brackets, and records which callbacks SQLite uses.
 */

#include <sqlite3.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct PepperPendingWrite PepperPendingWrite;
struct PepperPendingWrite {
  sqlite3_int64 offset;
  int amount;
  unsigned char *data;
  PepperPendingWrite *next;
};

typedef struct PepperSpikeFile PepperSpikeFile;
struct PepperSpikeFile {
  sqlite3_file base;
  sqlite3_file *real;
  PepperPendingWrite *writes_head;
  PepperPendingWrite *writes_tail;
  sqlite3_int64 truncate_size;
  int has_truncate;
  int in_batch;
};

static const char pepper_spike_name[] = "pepper-batch-spike";
static sqlite3_vfs *pepper_spike_vfs = 0;
static atomic_int pepper_begin_count = 0;
static atomic_int pepper_commit_count = 0;
static atomic_int pepper_rollback_count = 0;
static atomic_int pepper_fail_commit = 0;
static atomic_int pepper_exit_on_write = 0;
static atomic_int pepper_event_count = 0;
static atomic_int pepper_events[64];

enum {
  PEPPER_EVENT_BEGIN = 1,
  PEPPER_EVENT_COMMIT = 2,
  PEPPER_EVENT_ROLLBACK = 3,
};

static void pepper_record_event(int event) {
  int index = atomic_fetch_add(&pepper_event_count, 1);
  if (index >= 0 && index < 64) {
    atomic_store(&pepper_events[index], event);
  }
}

static int pepper_file_offset(void) {
  const int alignment = (int)_Alignof(sqlite3_file);
  return ((int)sizeof(PepperSpikeFile) + alignment - 1) & ~(alignment - 1);
}

static PepperSpikeFile *pepper_file(sqlite3_file *file) {
  return (PepperSpikeFile *)file;
}

static const sqlite3_io_methods *pepper_real_methods(sqlite3_file *file) {
  return pepper_file(file)->real->pMethods;
}

static void pepper_clear_writes(PepperSpikeFile *file) {
  PepperPendingWrite *write = file->writes_head;
  while (write != 0) {
    PepperPendingWrite *next = write->next;
    sqlite3_free(write->data);
    sqlite3_free(write);
    write = next;
  }
  file->writes_head = 0;
  file->writes_tail = 0;
  file->has_truncate = 0;
  file->truncate_size = 0;
}

static int pepper_close(sqlite3_file *raw_file) {
  PepperSpikeFile *file = pepper_file(raw_file);
  int result;
  pepper_clear_writes(file);
  result = file->real->pMethods->xClose(file->real);
  raw_file->pMethods = 0;
  return result;
}

static int pepper_read(sqlite3_file *raw_file, void *buffer, int amount,
                       sqlite3_int64 offset) {
  PepperSpikeFile *file = pepper_file(raw_file);
  PepperPendingWrite *write;
  int result = file->real->pMethods->xRead(file->real, buffer, amount, offset);
  if (!file->in_batch) {
    return result;
  }
  for (write = file->writes_head; write != 0; write = write->next) {
    sqlite3_int64 start = write->offset > offset ? write->offset : offset;
    sqlite3_int64 write_end = write->offset + write->amount;
    sqlite3_int64 read_end = offset + amount;
    sqlite3_int64 end = write_end < read_end ? write_end : read_end;
    if (start < end) {
      memcpy((unsigned char *)buffer + (size_t)(start - offset),
             write->data + (size_t)(start - write->offset),
             (size_t)(end - start));
      result = SQLITE_OK;
    }
  }
  return result;
}

static int pepper_write(sqlite3_file *raw_file, const void *buffer, int amount,
                        sqlite3_int64 offset) {
  PepperSpikeFile *file = pepper_file(raw_file);
  PepperPendingWrite *write;
  if (!file->in_batch) {
    return file->real->pMethods->xWrite(file->real, buffer, amount, offset);
  }
  if (atomic_exchange(&pepper_exit_on_write, 0)) {
    _Exit(86);
  }
  if (amount < 0 || offset < 0) {
    return SQLITE_IOERR_WRITE;
  }
  write = sqlite3_malloc64(sizeof(*write));
  if (write == 0) {
    return SQLITE_NOMEM;
  }
  memset(write, 0, sizeof(*write));
  write->data = sqlite3_malloc64((sqlite3_uint64)amount);
  if (write->data == 0) {
    sqlite3_free(write);
    return SQLITE_NOMEM;
  }
  memcpy(write->data, buffer, (size_t)amount);
  write->amount = amount;
  write->offset = offset;
  if (file->writes_tail == 0) {
    file->writes_head = write;
  } else {
    file->writes_tail->next = write;
  }
  file->writes_tail = write;
  return SQLITE_OK;
}

static int pepper_truncate(sqlite3_file *raw_file, sqlite3_int64 size) {
  PepperSpikeFile *file = pepper_file(raw_file);
  if (!file->in_batch) {
    return file->real->pMethods->xTruncate(file->real, size);
  }
  file->has_truncate = 1;
  file->truncate_size = size;
  return SQLITE_OK;
}

static int pepper_sync(sqlite3_file *file, int flags) {
  return pepper_file(file)->real->pMethods->xSync(pepper_file(file)->real,
                                                  flags);
}

static int pepper_file_size(sqlite3_file *raw_file, sqlite3_int64 *size) {
  PepperSpikeFile *file = pepper_file(raw_file);
  int result = file->real->pMethods->xFileSize(file->real, size);
  PepperPendingWrite *write;
  if (result != SQLITE_OK || !file->in_batch) {
    return result;
  }
  if (file->has_truncate) {
    *size = file->truncate_size;
  }
  for (write = file->writes_head; write != 0; write = write->next) {
    sqlite3_int64 end = write->offset + write->amount;
    if (end > *size) {
      *size = end;
    }
  }
  return SQLITE_OK;
}

static int pepper_lock(sqlite3_file *file, int lock) {
  return pepper_file(file)->real->pMethods->xLock(pepper_file(file)->real,
                                                  lock);
}

static int pepper_unlock(sqlite3_file *file, int lock) {
  return pepper_file(file)->real->pMethods->xUnlock(pepper_file(file)->real,
                                                    lock);
}

static int pepper_check_reserved(sqlite3_file *file, int *result) {
  return pepper_file(file)->real->pMethods->xCheckReservedLock(
      pepper_file(file)->real, result);
}

static int pepper_commit_pending(PepperSpikeFile *file) {
  PepperPendingWrite *write;
  int result = SQLITE_OK;
  for (write = file->writes_head; write != 0 && result == SQLITE_OK;
       write = write->next) {
    result = file->real->pMethods->xWrite(file->real, write->data,
                                          write->amount, write->offset);
  }
  if (result == SQLITE_OK && file->has_truncate) {
    result = file->real->pMethods->xTruncate(file->real, file->truncate_size);
  }
  if (result == SQLITE_OK) {
    result = file->real->pMethods->xSync(file->real, SQLITE_SYNC_FULL);
  }
  return result;
}

static int pepper_file_control(sqlite3_file *raw_file, int operation,
                               void *argument) {
  PepperSpikeFile *file = pepper_file(raw_file);
  (void)argument;
  switch (operation) {
  case SQLITE_FCNTL_BEGIN_ATOMIC_WRITE:
    if (file->in_batch) {
      return SQLITE_MISUSE;
    }
    pepper_clear_writes(file);
    file->in_batch = 1;
    atomic_fetch_add(&pepper_begin_count, 1);
    pepper_record_event(PEPPER_EVENT_BEGIN);
    return SQLITE_OK;
  case SQLITE_FCNTL_COMMIT_ATOMIC_WRITE: {
    int result;
    if (!file->in_batch) {
      return SQLITE_MISUSE;
    }
    atomic_fetch_add(&pepper_commit_count, 1);
    pepper_record_event(PEPPER_EVENT_COMMIT);
    if (atomic_exchange(&pepper_fail_commit, 0)) {
      return SQLITE_FULL;
    }
    result = pepper_commit_pending(file);
    if (result == SQLITE_OK) {
      pepper_clear_writes(file);
      file->in_batch = 0;
    }
    return result;
  }
  case SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE:
    atomic_fetch_add(&pepper_rollback_count, 1);
    pepper_record_event(PEPPER_EVENT_ROLLBACK);
    pepper_clear_writes(file);
    file->in_batch = 0;
    return SQLITE_OK;
  default:
    return file->real->pMethods->xFileControl(file->real, operation, argument);
  }
}

static int pepper_sector_size(sqlite3_file *file) {
  return pepper_file(file)->real->pMethods->xSectorSize(
      pepper_file(file)->real);
}

static int pepper_device_characteristics(sqlite3_file *file) {
  return pepper_file(file)->real->pMethods->xDeviceCharacteristics(
             pepper_file(file)->real) |
         SQLITE_IOCAP_BATCH_ATOMIC;
}

static int pepper_shm_map(sqlite3_file *file, int page, int page_size,
                          int extend, void volatile **result) {
  const sqlite3_io_methods *methods = pepper_real_methods(file);
  if (methods->iVersion < 2 || methods->xShmMap == 0) {
    return SQLITE_IOERR_SHMMAP;
  }
  return methods->xShmMap(pepper_file(file)->real, page, page_size, extend,
                          result);
}

static int pepper_shm_lock(sqlite3_file *file, int offset, int count,
                           int flags) {
  const sqlite3_io_methods *methods = pepper_real_methods(file);
  if (methods->iVersion < 2 || methods->xShmLock == 0) {
    return SQLITE_IOERR_SHMLOCK;
  }
  return methods->xShmLock(pepper_file(file)->real, offset, count, flags);
}

static void pepper_shm_barrier(sqlite3_file *file) {
  const sqlite3_io_methods *methods = pepper_real_methods(file);
  if (methods->iVersion >= 2 && methods->xShmBarrier != 0) {
    methods->xShmBarrier(pepper_file(file)->real);
  }
}

static int pepper_shm_unmap(sqlite3_file *file, int delete_flag) {
  const sqlite3_io_methods *methods = pepper_real_methods(file);
  if (methods->iVersion < 2 || methods->xShmUnmap == 0) {
    return SQLITE_OK;
  }
  return methods->xShmUnmap(pepper_file(file)->real, delete_flag);
}

static int pepper_fetch(sqlite3_file *file, sqlite3_int64 offset, int amount,
                        void **result) {
  const sqlite3_io_methods *methods = pepper_real_methods(file);
  if (methods->iVersion < 3 || methods->xFetch == 0) {
    *result = 0;
    return SQLITE_OK;
  }
  return methods->xFetch(pepper_file(file)->real, offset, amount, result);
}

static int pepper_unfetch(sqlite3_file *file, sqlite3_int64 offset,
                          void *pointer) {
  const sqlite3_io_methods *methods = pepper_real_methods(file);
  if (methods->iVersion < 3 || methods->xUnfetch == 0) {
    return SQLITE_OK;
  }
  return methods->xUnfetch(pepper_file(file)->real, offset, pointer);
}

static const sqlite3_io_methods pepper_io_methods = {
    3,
    pepper_close,
    pepper_read,
    pepper_write,
    pepper_truncate,
    pepper_sync,
    pepper_file_size,
    pepper_lock,
    pepper_unlock,
    pepper_check_reserved,
    pepper_file_control,
    pepper_sector_size,
    pepper_device_characteristics,
    pepper_shm_map,
    pepper_shm_lock,
    pepper_shm_barrier,
    pepper_shm_unmap,
    pepper_fetch,
    pepper_unfetch,
};

static int pepper_open(sqlite3_vfs *vfs, sqlite3_filename name,
                       sqlite3_file *raw_file, int flags, int *out_flags) {
  sqlite3_vfs *real_vfs = (sqlite3_vfs *)vfs->pAppData;
  PepperSpikeFile *file = pepper_file(raw_file);
  int result;
  memset(raw_file, 0, (size_t)vfs->szOsFile);
  file->real = (sqlite3_file *)((unsigned char *)raw_file +
                                pepper_file_offset());
  result = real_vfs->xOpen(real_vfs, name, file->real, flags, out_flags);
  if (result != SQLITE_OK) {
    raw_file->pMethods = 0;
    return result;
  }
  raw_file->pMethods = &pepper_io_methods;
  return SQLITE_OK;
}

int pepper_batch_spike_register(void) {
  sqlite3_vfs *real_vfs;
  int result;
  if (pepper_spike_vfs != 0) {
    return SQLITE_OK;
  }
  real_vfs = sqlite3_vfs_find(0);
  if (real_vfs == 0) {
    return SQLITE_NOTFOUND;
  }
  pepper_spike_vfs = sqlite3_malloc64(sizeof(*pepper_spike_vfs));
  if (pepper_spike_vfs == 0) {
    return SQLITE_NOMEM;
  }
  memcpy(pepper_spike_vfs, real_vfs, sizeof(*pepper_spike_vfs));
  pepper_spike_vfs->pNext = 0;
  pepper_spike_vfs->zName = pepper_spike_name;
  pepper_spike_vfs->pAppData = real_vfs;
  pepper_spike_vfs->szOsFile = pepper_file_offset() + real_vfs->szOsFile;
  pepper_spike_vfs->xOpen = pepper_open;
  result = sqlite3_vfs_register(pepper_spike_vfs, 0);
  if (result != SQLITE_OK) {
    sqlite3_free(pepper_spike_vfs);
    pepper_spike_vfs = 0;
  }
  return result;
}

int pepper_batch_spike_unregister(void) {
  int result;
  if (pepper_spike_vfs == 0) {
    return SQLITE_OK;
  }
  result = sqlite3_vfs_unregister(pepper_spike_vfs);
  if (result == SQLITE_OK) {
    sqlite3_free(pepper_spike_vfs);
    pepper_spike_vfs = 0;
  }
  return result;
}

void pepper_batch_spike_reset(void) {
  int index;
  atomic_store(&pepper_begin_count, 0);
  atomic_store(&pepper_commit_count, 0);
  atomic_store(&pepper_rollback_count, 0);
  atomic_store(&pepper_fail_commit, 0);
  atomic_store(&pepper_exit_on_write, 0);
  atomic_store(&pepper_event_count, 0);
  for (index = 0; index < 64; index++) {
    atomic_store(&pepper_events[index], 0);
  }
}

void pepper_batch_spike_fail_next_commit(void) {
  atomic_store(&pepper_fail_commit, 1);
}

void pepper_batch_spike_exit_on_batch_write(void) {
  atomic_store(&pepper_exit_on_write, 1);
}

int pepper_batch_spike_begin_count(void) {
  return atomic_load(&pepper_begin_count);
}

int pepper_batch_spike_commit_count(void) {
  return atomic_load(&pepper_commit_count);
}

int pepper_batch_spike_rollback_count(void) {
  return atomic_load(&pepper_rollback_count);
}

int pepper_batch_spike_event_count(void) {
  int count = atomic_load(&pepper_event_count);
  return count < 64 ? count : 64;
}

int pepper_batch_spike_event_at(int index) {
  if (index < 0 || index >= 64) {
    return 0;
  }
  return atomic_load(&pepper_events[index]);
}
