/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __EXEC_SKEL_H__
#define __EXEC_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct exec {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *handle_execve;
	} progs;
	struct {
		struct bpf_link *handle_execve;
	} links;

#ifdef __cplusplus
	static inline struct exec *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct exec *open_and_load();
	static inline int load(struct exec *skel);
	static inline int attach(struct exec *skel);
	static inline void detach(struct exec *skel);
	static inline void destroy(struct exec *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
exec__destroy(struct exec *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
exec__create_skeleton(struct exec *obj);

static inline struct exec *
exec__open_opts(const struct bpf_object_open_opts *opts)
{
	struct exec *obj;
	int err;

	obj = (struct exec *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = exec__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	exec__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct exec *
exec__open(void)
{
	return exec__open_opts(NULL);
}

static inline int
exec__load(struct exec *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct exec *
exec__open_and_load(void)
{
	struct exec *obj;
	int err;

	obj = exec__open();
	if (!obj)
		return NULL;
	err = exec__load(obj);
	if (err) {
		exec__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
exec__attach(struct exec *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
exec__detach(struct exec *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *exec__elf_bytes(size_t *sz);

static inline int
exec__create_skeleton(struct exec *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "exec";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "exec.rodata";
	s->maps[0].map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "handle_execve";
	s->progs[0].prog = &obj->progs.handle_execve;
	s->progs[0].link = &obj->links.handle_execve;

	s->data = exec__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *exec__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x10\x0b\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1a\0\
\x01\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x0d\0\0\0\x85\0\0\0\x06\
\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x45\x78\x65\x63\x20\x43\x61\x6c\x6c\
\x65\x64\x0a\0\x47\x50\x4c\0\x01\x11\x01\x25\x25\x13\x05\x03\x25\x72\x17\x10\
\x17\x1b\x25\x11\x1b\x12\x06\x73\x17\0\0\x02\x2e\x01\x11\x1b\x12\x06\x40\x18\
\x7a\x19\x03\x25\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x3f\x19\0\0\x03\x34\0\x03\x25\
\x49\x13\x3a\x0b\x3b\x0b\x02\x18\0\0\x04\x05\0\x03\x25\x3a\x0b\x3b\x0b\x49\x13\
\0\0\x05\x01\x01\x49\x13\0\0\x06\x21\0\x49\x13\x37\x0b\0\0\x07\x26\0\x49\x13\0\
\0\x08\x24\0\x03\x25\x3e\x0b\x0b\x0b\0\0\x09\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\
\x0a\x34\0\x03\x25\x49\x13\x3f\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x0b\x34\0\x03\
\x25\x49\x13\x3a\x0b\x3b\x0b\0\0\x0c\x0f\0\x49\x13\0\0\x0d\x15\x01\x49\x13\x27\
\x19\0\0\x0e\x05\0\x49\x13\0\0\x0f\x18\0\0\0\x10\x16\0\x49\x13\x03\x25\x3a\x0b\
\x3b\x0b\0\0\x11\x0f\0\0\0\0\xab\0\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x0c\0\x01\
\x08\0\0\0\0\0\0\0\x02\x02\x30\0\0\0\x08\0\0\0\x02\x02\x30\0\0\0\x01\x5a\x0b\0\
\x05\xa9\0\0\0\x03\x03\x46\0\0\0\0\x07\x02\xa1\0\x04\x0d\0\x05\xad\0\0\0\0\x05\
\x52\0\0\0\x06\x5b\0\0\0\x0d\0\x07\x57\0\0\0\x08\x04\x06\x01\x09\x05\x08\x07\
\x0a\x06\x6a\0\0\0\0\x0b\x02\xa1\x01\x05\x57\0\0\0\x06\x5b\0\0\0\x04\0\x0b\x07\
\x7e\0\0\0\x02\xb1\x0c\x83\0\0\0\x0d\x94\0\0\0\x0e\x98\0\0\0\x0e\x9d\0\0\0\x0f\
\0\x08\x08\x05\x08\x0c\x52\0\0\0\x10\xa5\0\0\0\x0a\x01\x12\x08\x09\x07\x04\x08\
\x0c\x05\x04\x11\0\x3c\0\0\0\x05\0\0\0\0\0\0\0\x27\0\0\0\x32\0\0\0\x50\0\0\0\
\x58\0\0\0\x5d\0\0\0\x71\0\0\0\x79\0\0\0\x8a\0\0\0\x8f\0\0\0\x9c\0\0\0\xa2\0\0\
\0\xb0\0\0\0\xb4\0\0\0\x55\x62\x75\x6e\x74\x75\x20\x63\x6c\x61\x6e\x67\x20\x76\
\x65\x72\x73\x69\x6f\x6e\x20\x31\x34\x2e\x30\x2e\x30\x2d\x31\x75\x62\x75\x6e\
\x74\x75\x31\x2e\x31\0\x65\x78\x65\x63\x2e\x62\x70\x66\x2e\x63\0\x2f\x68\x6f\
\x6d\x65\x2f\x61\x6c\x69\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x65\x42\x50\x46\
\x2f\x73\x69\x6d\x70\x6c\x65\0\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x63\x68\x61\x72\0\
\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\
\x4c\x49\x43\x45\x4e\x53\x45\0\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\
\x69\x6e\x74\x6b\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x5f\x5f\x75\x33\x32\0\x68\x61\x6e\x64\x6c\x65\x5f\x65\x78\x65\x63\
\x76\x65\0\x69\x6e\x74\0\x63\x74\x78\0\x1c\0\0\0\x05\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\xe8\0\0\0\
\xe8\0\0\0\xd3\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\x01\0\0\x0d\x03\0\0\0\
\x01\0\0\0\x01\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x09\0\0\0\x01\0\
\0\x0c\x02\0\0\0\0\0\0\0\0\0\0\x0a\x06\0\0\0\x8c\0\0\0\0\0\0\x01\x01\0\0\0\x08\
\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x05\0\0\0\x08\0\0\0\x0d\0\0\0\x91\0\0\0\0\0\
\0\x01\x04\0\0\0\x20\0\0\0\xa5\0\0\0\0\0\0\x0e\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\0\x06\0\0\0\x08\0\0\0\x04\0\0\0\xbb\0\0\0\0\0\0\x0e\x0a\0\0\0\x01\0\
\0\0\xc3\0\0\0\x01\0\0\x0f\0\0\0\0\x09\0\0\0\0\0\0\0\x0d\0\0\0\xcb\0\0\0\x01\0\
\0\x0f\0\0\0\0\x0b\0\0\0\0\0\0\0\x04\0\0\0\0\x63\x74\x78\0\x69\x6e\x74\0\x68\
\x61\x6e\x64\x6c\x65\x5f\x65\x78\x65\x63\x76\x65\0\x74\x70\x2f\x73\x79\x73\x63\
\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\
\x76\x65\0\x2f\x68\x6f\x6d\x65\x2f\x61\x6c\x69\x2f\x44\x65\x73\x6b\x74\x6f\x70\
\x2f\x65\x42\x50\x46\x2f\x73\x69\x6d\x70\x6c\x65\x2f\x65\x78\x65\x63\x2e\x62\
\x70\x66\x2e\x63\0\x20\x20\x20\x20\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\
\x22\x45\x78\x65\x63\x20\x43\x61\x6c\x6c\x65\x64\x5c\x6e\x22\x29\x3b\0\x20\x20\
\x20\x20\x72\x65\x74\x75\x72\x6e\x20\x30\x3b\0\x63\x68\x61\x72\0\x5f\x5f\x41\
\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x68\x61\x6e\
\x64\x6c\x65\x5f\x65\x78\x65\x63\x76\x65\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x4c\
\x49\x43\x45\x4e\x53\x45\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\
\x73\x65\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x2c\0\0\0\x40\
\0\0\0\0\0\0\0\x08\0\0\0\x17\0\0\0\x01\0\0\0\0\0\0\0\x04\0\0\0\x10\0\0\0\x17\0\
\0\0\x02\0\0\0\0\0\0\0\x34\0\0\0\x5d\0\0\0\x05\x1c\0\0\x20\0\0\0\x34\0\0\0\x7e\
\0\0\0\x05\x20\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\
\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x89\0\0\0\x05\0\x08\0\x69\
\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\x01\x01\x1f\
\x03\0\0\0\0\x1e\0\0\0\x20\0\0\0\x03\x01\x1f\x02\x0f\x05\x1e\x03\x31\0\0\0\0\
\x35\x04\xbf\x39\x43\xc7\xa6\xdf\xcc\x38\xcd\xfe\xe7\xdc\xbf\x08\x3c\0\0\0\x01\
\x90\xd9\x55\xc2\x8c\x4d\xca\xbd\xd9\xfb\x22\xa6\x0b\xd2\xc7\x14\x46\0\0\0\x02\
\x52\x60\xf0\x6f\x90\xb9\x4e\xed\x43\xb7\x46\xc4\x5e\x48\x28\xc2\x04\0\0\x09\
\x02\0\0\0\0\0\0\0\0\x17\x05\x05\x0a\x13\x4b\x02\x02\0\x01\x01\x2f\x68\x6f\x6d\
\x65\x2f\x61\x6c\x69\x2f\x44\x65\x73\x6b\x74\x6f\x70\x2f\x65\x42\x50\x46\x2f\
\x73\x69\x6d\x70\x6c\x65\0\x2e\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\
\x65\x2f\x62\x70\x66\0\x65\x78\x65\x63\x2e\x62\x70\x66\x2e\x63\0\x76\x6d\x6c\
\x69\x6e\x75\x78\x2e\x68\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\
\x66\x73\x2e\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\0\
\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x01\0\x05\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x07\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0d\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x13\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\x15\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb9\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\
\0\0\0\x1c\x01\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\x04\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x05\0\0\0\x11\0\0\0\0\0\0\0\
\x03\0\0\0\x06\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x0a\0\0\0\x1f\0\0\0\0\0\0\0\
\x03\0\0\0\x08\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x0c\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x1c\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x24\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x2c\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x34\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\x07\0\0\0\x3c\0\0\0\0\0\0\0\
\x03\0\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\x02\0\0\0\x04\0\0\0\x10\0\0\0\0\0\0\0\
\x02\0\0\0\x0d\0\0\0\x18\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\xe0\0\0\0\0\0\0\0\
\x03\0\0\0\x04\0\0\0\xf8\0\0\0\0\0\0\0\x04\0\0\0\x0d\0\0\0\x2c\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x18\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x26\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x2a\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x36\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x4b\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x60\0\0\0\0\0\0\0\
\x03\0\0\0\x0b\0\0\0\x7a\0\0\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x0c\x03\x0d\0\x2e\
\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\
\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x68\x61\x6e\x64\x6c\x65\x5f\x65\
\x78\x65\x63\x76\x65\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x72\x65\x6c\x2e\x64\
\x65\x62\x75\x67\x5f\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x64\x65\
\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\x5f\
\x73\x74\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x61\x64\x64\x72\0\
\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\x6c\x76\
\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x2e\x72\x65\x6c\x74\x70\x2f\x73\x79\x73\
\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\
\x63\x76\x65\0\x68\x61\x6e\x64\x6c\x65\x5f\x65\x78\x65\x63\x76\x65\0\x6c\x69\
\x63\x65\x6e\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\
\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x65\
\x78\x65\x63\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\
\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\x6c\x2e\x42\
\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xfb\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xeb\x09\0\0\
\0\0\0\0\x24\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9c\0\0\0\x01\0\0\
\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\0\0\0\x09\0\0\0\x40\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xa8\x07\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x03\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\x01\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xc7\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x7d\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x81\0\0\0\0\0\0\0\
\xc6\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7e\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x47\x01\0\0\0\0\0\0\xaf\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7a\0\0\0\x09\0\0\0\x40\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb8\x07\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x19\0\0\0\
\x08\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x3c\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xf6\x01\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xf8\x07\0\0\0\0\0\0\xe0\0\0\0\0\0\0\0\x19\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\x4f\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x36\x02\0\0\0\0\0\0\xb8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\x6e\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xee\x02\0\0\0\
\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6a\
\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd8\x08\0\0\0\0\0\0\x30\0\0\
\0\0\0\0\0\x19\0\0\0\x0d\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x17\x01\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x10\x03\0\0\0\0\0\0\xd3\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x13\x01\0\0\x09\0\0\0\
\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\x09\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x19\0\
\0\0\x0f\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x28\x09\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x19\0\0\0\x11\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\xe3\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x48\x05\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xdf\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\x09\0\0\0\
\0\0\0\x20\0\0\0\0\0\0\0\x19\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\xd3\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\x05\0\0\0\0\0\0\x8d\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcf\0\0\0\x09\
\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x09\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\
\x19\0\0\0\x15\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x5a\0\0\0\x01\0\0\0\
\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfd\x05\0\0\0\0\0\0\x58\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x8a\0\0\0\x03\x4c\xff\x6f\0\0\0\
\x80\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x09\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\x19\0\0\0\0\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x58\x06\0\0\0\0\0\0\x50\x01\0\0\0\0\0\0\x01\0\0\0\x0c\0\0\0\
\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct exec *exec::open(const struct bpf_object_open_opts *opts) { return exec__open_opts(opts); }
struct exec *exec::open_and_load() { return exec__open_and_load(); }
int exec::load(struct exec *skel) { return exec__load(skel); }
int exec::attach(struct exec *skel) { return exec__attach(skel); }
void exec::detach(struct exec *skel) { exec__detach(skel); }
void exec::destroy(struct exec *skel) { exec__destroy(skel); }
const void *exec::elf_bytes(size_t *sz) { return exec__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
exec__assert(struct exec *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __EXEC_SKEL_H__ */
