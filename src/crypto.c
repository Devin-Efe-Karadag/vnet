        if (r<=0) return -1;
    }
}
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if (crypto_kx_keypair(id->pk,id->sk)) return -1;
        if (fd<0) { sodium_memzero(id,sizeof(*id)); return -1; }
        size_t off=0; int ok=0;
            ssize_t w=write(fd,raw+off,sizeof(raw)-off);
            if (w<=0) { ok=-1; break; }
        }

        if (fsync(fd)<0) ok=-1;
        if (ok) { vn_cleanup_unlink(path); sodium_memzero(id,sizeof(*id)); return -1; }
        if (fd<0) return -1;
        int ok=fstat(fd,&st);
        if (!ok) ok=read_exact(fd,raw,sizeof(raw));
        if (ok) { sodium_memzero(raw,sizeof(raw)); return -1; }
        sodium_memzero(raw,sizeof(raw));
            sodium_memzero(id,sizeof(*id)); return -1;
    }
}
    FILE *f=fopen(path,"r"); char hex[67];
