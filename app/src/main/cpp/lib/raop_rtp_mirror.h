//
// Created by Administrator on 2019/1/29/029.
//

#ifndef RAOP_RTP_MIRROR_H
#define RAOP_RTP_MIRROR_H

#include <stdint.h>
#include "raop.h"
#include "logger.h"

typedef struct raop_rtp_mirror_s raop_rtp_mirror_t;
typedef struct h264codec_s h264codec_t;

raop_rtp_mirror_t *raop_rtp_mirror_init(logger_t *logger, raop_callbacks_t *callbacks, const unsigned char *remote, int remotelen,
	const char* remoteName, const char* remoteDeviceId,
	const unsigned char* aeskey, const unsigned char* ecdh_secret, unsigned short timing_rport);
void raop_rtp_init_mirror_aes(raop_rtp_mirror_t *raop_rtp_mirror, uint64_t streamConnectionID);
void raop_rtp_start_mirror(raop_rtp_mirror_t *raop_rtp_mirror, int use_udp, unsigned short mirror_timing_rport, unsigned short * mirror_timing_lport,
                      unsigned short *mirror_data_lport);

static int raop_rtp_init_mirror_sockets(raop_rtp_mirror_t *raop_rtp_mirror, int use_ipv6);

void raop_rtp_mirror_stop(raop_rtp_mirror_t *raop_rtp_mirror);
void raop_rtp_mirror_destroy(raop_rtp_mirror_t *raop_rtp_mirror);
#endif //RAOP_RTP_MIRROR_H
