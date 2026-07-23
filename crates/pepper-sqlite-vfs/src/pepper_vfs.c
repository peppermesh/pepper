/* SPDX-License-Identifier: Apache-2.0 */

#include <sqlite3.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int pepper_rust_open(const char *, int, void **);
extern int pepper_rust_close(void *);
extern int pepper_rust_read(void *, void *, int, sqlite3_int64);
extern int pepper_rust_write(void *, const void *, int, sqlite3_int64);
extern int pepper_rust_truncate(void *, sqlite3_int64);
extern int pepper_rust_sync(void *);
extern int pepper_rust_file_size(void *, sqlite3_int64 *);
extern int pepper_rust_lock(void *, int);
extern int pepper_rust_unlock(void *, int);
extern int pepper_rust_file_control(void *, int);

typedef struct PepperFile PepperFile;
struct PepperFile {
  sqlite3_file base;
  int remote;
  int atomic_sidecar;
  void *rust_file;
  sqlite3_file *real;
};

static sqlite3_vfs *pepper_vfs = 0;
static const char pepper_vfs_name[] = "pepper";

static int real_offset(void) {
  const int alignment = (int)_Alignof(sqlite3_file);
  return ((int)sizeof(PepperFile) + alignment - 1) & ~(alignment - 1);
}

static PepperFile *pepper_file(sqlite3_file *file) {
  return (PepperFile *)file;
}

#define DELEGATE(file, method, ...)                                           \
  (pepper_file(file)->real->pMethods->method(pepper_file(file)->real,          \
                                              __VA_ARGS__))

static int p_close(sqlite3_file *raw) {
  PepperFile *file = pepper_file(raw);
  int result = file->remote ? pepper_rust_close(file->rust_file)
                            : file->real->pMethods->xClose(file->real);
  raw->pMethods = 0;
  file->rust_file = 0;
  return result;
}

static int p_read(sqlite3_file *raw, void *buffer, int amount,
                  sqlite3_int64 offset) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? pepper_rust_read(file->rust_file, buffer, amount, offset)
                      : DELEGATE(raw, xRead, buffer, amount, offset);
}

static int p_write(sqlite3_file *raw, const void *buffer, int amount,
                   sqlite3_int64 offset) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? pepper_rust_write(file->rust_file, buffer, amount, offset)
                      : DELEGATE(raw, xWrite, buffer, amount, offset);
}

static int p_truncate(sqlite3_file *raw, sqlite3_int64 size) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? pepper_rust_truncate(file->rust_file, size)
                      : DELEGATE(raw, xTruncate, size);
}

static int p_sync(sqlite3_file *raw, int flags) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? pepper_rust_sync(file->rust_file)
                      : DELEGATE(raw, xSync, flags);
}

static int p_file_size(sqlite3_file *raw, sqlite3_int64 *size) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? pepper_rust_file_size(file->rust_file, size)
                      : DELEGATE(raw, xFileSize, size);
}

static int p_lock(sqlite3_file *raw, int level) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? pepper_rust_lock(file->rust_file, level)
                      : DELEGATE(raw, xLock, level);
}

static int p_unlock(sqlite3_file *raw, int level) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? pepper_rust_unlock(file->rust_file, level)
                      : DELEGATE(raw, xUnlock, level);
}

static int p_check_reserved(sqlite3_file *raw, int *result) {
  PepperFile *file = pepper_file(raw);
  if (file->remote) {
    *result = 0;
    return SQLITE_OK;
  }
  return DELEGATE(raw, xCheckReservedLock, result);
}

static int p_file_control(sqlite3_file *raw, int operation, void *argument) {
  PepperFile *file = pepper_file(raw);
  if (!file->remote) {
    if (file->atomic_sidecar &&
        (operation == SQLITE_FCNTL_BEGIN_ATOMIC_WRITE ||
         operation == SQLITE_FCNTL_COMMIT_ATOMIC_WRITE ||
         operation == SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE))
      return SQLITE_OK;
    return DELEGATE(raw, xFileControl, operation, argument);
  }
  if (operation == SQLITE_FCNTL_MMAP_SIZE) {
    if (argument != 0) {
      /* SQLite passes exactly one sqlite3_int64 and expects the prior limit. */
      *(sqlite3_int64 *)argument = 0;
    }
    return SQLITE_OK;
  }
  if (operation == SQLITE_FCNTL_HAS_MOVED) {
    if (argument != 0) {
      *(int *)argument = 0;
    }
    return SQLITE_OK;
  }
  return pepper_rust_file_control(file->rust_file, operation);
}

static int p_sector_size(sqlite3_file *raw) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? 4096 : file->real->pMethods->xSectorSize(file->real);
}

static int p_device_characteristics(sqlite3_file *raw) {
  PepperFile *file = pepper_file(raw);
  return file->remote ? SQLITE_IOCAP_BATCH_ATOMIC
                      : file->real->pMethods->xDeviceCharacteristics(file->real) |
                            (file->atomic_sidecar ? SQLITE_IOCAP_BATCH_ATOMIC : 0);
}

static int p_shm_map(sqlite3_file *raw, int page, int size, int extend,
                     void volatile **result) {
  PepperFile *file = pepper_file(raw);
  if (file->remote) {
    (void)page; (void)size; (void)extend; *result = 0;
    return SQLITE_IOERR_SHMMAP;
  }
  if (file->real->pMethods->iVersion < 2 || file->real->pMethods->xShmMap == 0)
    return SQLITE_IOERR_SHMMAP;
  return file->real->pMethods->xShmMap(file->real, page, size, extend, result);
}

static int p_shm_lock(sqlite3_file *raw, int offset, int count, int flags) {
  PepperFile *file = pepper_file(raw);
  if (file->remote) return SQLITE_IOERR_SHMLOCK;
  if (file->real->pMethods->iVersion < 2 || file->real->pMethods->xShmLock == 0)
    return SQLITE_IOERR_SHMLOCK;
  return file->real->pMethods->xShmLock(file->real, offset, count, flags);
}

static void p_shm_barrier(sqlite3_file *raw) {
  PepperFile *file = pepper_file(raw);
  if (!file->remote && file->real->pMethods->iVersion >= 2 &&
      file->real->pMethods->xShmBarrier != 0)
    file->real->pMethods->xShmBarrier(file->real);
}

static int p_shm_unmap(sqlite3_file *raw, int delete_flag) {
  PepperFile *file = pepper_file(raw);
  if (file->remote) return SQLITE_OK;
  if (file->real->pMethods->iVersion < 2 || file->real->pMethods->xShmUnmap == 0)
    return SQLITE_OK;
  return file->real->pMethods->xShmUnmap(file->real, delete_flag);
}

static int p_fetch(sqlite3_file *raw, sqlite3_int64 offset, int amount,
                   void **result) {
  PepperFile *file = pepper_file(raw);
  if (file->remote) {
    (void)offset; (void)amount; *result = 0; return SQLITE_OK;
  }
  if (file->real->pMethods->iVersion < 3 || file->real->pMethods->xFetch == 0) {
    *result = 0; return SQLITE_OK;
  }
  return file->real->pMethods->xFetch(file->real, offset, amount, result);
}

static int p_unfetch(sqlite3_file *raw, sqlite3_int64 offset, void *pointer) {
  PepperFile *file = pepper_file(raw);
  if (file->remote) return SQLITE_OK;
  if (file->real->pMethods->iVersion < 3 || file->real->pMethods->xUnfetch == 0)
    return SQLITE_OK;
  return file->real->pMethods->xUnfetch(file->real, offset, pointer);
}

static const sqlite3_io_methods pepper_methods = {
  3, p_close, p_read, p_write, p_truncate, p_sync, p_file_size,
  p_lock, p_unlock, p_check_reserved, p_file_control, p_sector_size,
  p_device_characteristics, p_shm_map, p_shm_lock, p_shm_barrier,
  p_shm_unmap, p_fetch, p_unfetch
};

static int is_pepper_name(const char *name) {
  return name != 0 &&
         (strncmp(name, "pepper:", 7) == 0 ||
          strncmp(name, "file:pepper:", 12) == 0);
}

static int p_open(sqlite3_vfs *vfs, sqlite3_filename name,
                  sqlite3_file *raw, int flags, int *out_flags) {
  sqlite3_vfs *real = (sqlite3_vfs *)vfs->pAppData;
  PepperFile *file = pepper_file(raw);
  int result;
  memset(raw, 0, (size_t)vfs->szOsFile);
  if ((flags & SQLITE_OPEN_MAIN_DB) != 0 && is_pepper_name(name)) {
    const char *mode = sqlite3_uri_parameter(name, "mode");
    const char *snapshot = sqlite3_uri_parameter(name, "snapshot");
    const char *busy = sqlite3_uri_parameter(name, "busy_timeout_ms");
    char *canonical;
    file->remote = 1;
    if (mode == 0)
      mode = (flags & SQLITE_OPEN_READONLY) != 0 ? "ro" :
             ((flags & SQLITE_OPEN_CREATE) != 0 ? "rwc" : "rw");
    if (snapshot != 0 && busy != 0)
      canonical = sqlite3_mprintf(
          "%s?mode=%s&snapshot=%s&busy_timeout_ms=%s",
          name, mode, snapshot, busy);
    else if (snapshot != 0)
      canonical = sqlite3_mprintf("%s?mode=%s&snapshot=%s",
                                  name, mode, snapshot);
    else if (busy != 0)
      canonical = sqlite3_mprintf("%s?mode=%s&busy_timeout_ms=%s",
                                  name, mode, busy);
    else
      canonical = sqlite3_mprintf("%s?mode=%s", name, mode);
    if (canonical == 0) return SQLITE_NOMEM;
    result = pepper_rust_open(canonical, flags, &file->rust_file);
    sqlite3_free(canonical);
    if (result == SQLITE_OK) {
      raw->pMethods = &pepper_methods;
      if (out_flags != 0) *out_flags = flags;
    }
    return result;
  }
  if (is_pepper_name(name)) {
    int temporary_flags;
    /* Rollback journals may be requested before SQLite enters the atomic
       batch. Keep them anonymous and delete-on-close; they are never truth. */
    if ((flags & SQLITE_OPEN_MAIN_JOURNAL) == 0) return SQLITE_CANTOPEN;
    temporary_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                      SQLITE_OPEN_DELETEONCLOSE | SQLITE_OPEN_TEMP_JOURNAL;
    file->real = (sqlite3_file *)((unsigned char *)raw + real_offset());
    file->atomic_sidecar = 1;
    result = real->xOpen(real, 0, file->real, temporary_flags, out_flags);
    if (result == SQLITE_OK) raw->pMethods = &pepper_methods;
    return result;
  }
  file->real = (sqlite3_file *)((unsigned char *)raw + real_offset());
  result = real->xOpen(real, name, file->real, flags, out_flags);
  if (result == SQLITE_OK) raw->pMethods = &pepper_methods;
  return result;
}

static int p_delete(sqlite3_vfs *vfs, const char *name, int sync_dir) {
  if (is_pepper_name(name)) return SQLITE_OK;
  return ((sqlite3_vfs *)vfs->pAppData)->xDelete(
      (sqlite3_vfs *)vfs->pAppData, name, sync_dir);
}

static int p_access(sqlite3_vfs *vfs, const char *name, int flags, int *result) {
  if (is_pepper_name(name)) { *result = 0; return SQLITE_OK; }
  return ((sqlite3_vfs *)vfs->pAppData)->xAccess(
      (sqlite3_vfs *)vfs->pAppData, name, flags, result);
}

static int p_full_path(sqlite3_vfs *vfs, const char *name, int size, char *out) {
  if (is_pepper_name(name)) {
    size_t length = strlen(name);
    if (length + 1 > (size_t)size) return SQLITE_CANTOPEN;
    memcpy(out, name, length + 1);
    return SQLITE_OK;
  }
  return ((sqlite3_vfs *)vfs->pAppData)->xFullPathname(
      (sqlite3_vfs *)vfs->pAppData, name, size, out);
}

int pepper_production_vfs_register(void) {
  sqlite3_vfs *real;
  int result;
  if (pepper_vfs != 0) return SQLITE_OK;
  real = sqlite3_vfs_find(0);
  if (real == 0) return SQLITE_NOTFOUND;
  pepper_vfs = sqlite3_malloc64(sizeof(*pepper_vfs));
  if (pepper_vfs == 0) return SQLITE_NOMEM;
  memcpy(pepper_vfs, real, sizeof(*pepper_vfs));
  pepper_vfs->pNext = 0;
  pepper_vfs->zName = pepper_vfs_name;
  pepper_vfs->pAppData = real;
  pepper_vfs->szOsFile = real_offset() + real->szOsFile;
  pepper_vfs->xOpen = p_open;
  pepper_vfs->xDelete = p_delete;
  pepper_vfs->xAccess = p_access;
  pepper_vfs->xFullPathname = p_full_path;
  result = sqlite3_vfs_register(pepper_vfs, 0);
  if (result != SQLITE_OK) { sqlite3_free(pepper_vfs); pepper_vfs = 0; }
  return result;
}

int pepper_production_vfs_unregister(void) {
  int result;
  if (pepper_vfs == 0) return SQLITE_OK;
  result = sqlite3_vfs_unregister(pepper_vfs);
  if (result == SQLITE_OK) { sqlite3_free(pepper_vfs); pepper_vfs = 0; }
  return result;
}
