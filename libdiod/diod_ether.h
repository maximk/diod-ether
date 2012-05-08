#ifndef DIOD_ETHER_H
#define DIOD_ETHER_H

typedef struct diod_ether_t diod_ether_t;

diod_ether_t *diod_ether_create(void);
int diod_ether_listen(diod_ether_t *ether);
void diod_ether_accept_one(Npsrv *srv, diod_ether_t *ether);
void diod_ether_shutdown(diod_ether_t *ether);
void diod_ether_destroy(diod_ether_t *ether);

#endif
