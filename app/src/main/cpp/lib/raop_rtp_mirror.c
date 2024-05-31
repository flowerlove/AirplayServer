//
// Created by Administrator on 2019/1/29/029.
//

#include "raop_rtp_mirror.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "raop.h"
#include "netutils.h"
#include "compat.h"
#include "logger.h"
#include "byteutils.h"
#include "mirror_buffer.h"
#include "stream.h"


struct h264codec_s {
    unsigned char compatibility;
    short lengthofPPS;
    short lengthofSPS;
    unsigned char level;
    unsigned char numberOfPPS;
    unsigned char* picture_parameter_set;
    unsigned char profile_high;
    unsigned char reserved3andSPS;
    unsigned char reserved6andNAL;
    unsigned char* sequence;
    unsigned char version;
};

struct raop_rtp_mirror_s {
    logger_t *logger;
    raop_callbacks_t callbacks;

    /* Buffer to handle all resends */
    mirror_buffer_t *buffer;

    raop_rtp_mirror_t *mirror;
    /* Remote address as sockaddr */
    struct sockaddr_storage remote_saddr;
    socklen_t remote_saddr_len;
	const char remoteName[128];
	const char remoteDeviceId[128];

    /* MUTEX LOCKED VARIABLES START */
    /* These variables only edited mutex locked */
    int running;
    int joined;
    int time_mutex_destroyed;
    int run_mutex_destroyed;
    int time_cond_destroyed;
    int flush;
    thread_handle_t thread_mirror;
    thread_handle_t thread_time;
    // For thread_mirror exit unexpeced.
    thread_handle_t thread_exit_exception;
    mutex_handle_t run_mutex;

    mutex_handle_t time_mutex;
    cond_handle_t time_cond;
    /* MUTEX LOCKED VARIABLES END */
    int mirror_data_sock, mirror_time_sock;

    unsigned short mirror_data_lport;
    unsigned short mirror_timing_rport;
    unsigned short mirror_timing_lport;
};

static int
raop_rtp_parse_remote(raop_rtp_mirror_t *raop_rtp_mirror, const unsigned char *remote, int remotelen)
{
    char current[25];
    int family;
    int ret;
    assert(raop_rtp_mirror);
    if (remotelen == 4) {
        family = AF_INET;
    } else if (remotelen == 16) {
        family = AF_INET6;
    } else {
        return -1;
    }
    memset(current, 0, sizeof(current));
    sprintf(current, "%d.%d.%d.%d", remote[0], remote[1], remote[2], remote[3]);
    logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "raop_rtp_parse_remote ip = %s", current);
    ret = netutils_parse_address(family, current,
                                 &raop_rtp_mirror->remote_saddr,
                                 sizeof(raop_rtp_mirror->remote_saddr));
    if (ret < 0) {
        return -1;
    }
    raop_rtp_mirror->remote_saddr_len = ret;
    return 0;
}

#define NO_FLUSH (-42)
raop_rtp_mirror_t *raop_rtp_mirror_init(logger_t *logger, raop_callbacks_t *callbacks, const unsigned char *remote, int remotelen,
	                                    const char* remoteName, const char* remoteDeviceId,
                                        const unsigned char *aeskey, const unsigned char *ecdh_secret, unsigned short timing_rport)
{
    raop_rtp_mirror_t *raop_rtp_mirror;

    assert(logger);
    assert(callbacks);

    raop_rtp_mirror = calloc(1, sizeof(raop_rtp_mirror_t));
    if (!raop_rtp_mirror) {
        return NULL;
    }
    raop_rtp_mirror->logger = logger;
    raop_rtp_mirror->mirror_timing_rport = timing_rport;

    memcpy(&raop_rtp_mirror->callbacks, callbacks, sizeof(raop_callbacks_t));
    raop_rtp_mirror->buffer = mirror_buffer_init(logger, aeskey, ecdh_secret);
    if (!raop_rtp_mirror->buffer) {
        free(raop_rtp_mirror);
        return NULL;
    }
    if (raop_rtp_parse_remote(raop_rtp_mirror, remote, remotelen) < 0) {
        free(raop_rtp_mirror);
        return NULL;
    }
	memset(raop_rtp_mirror->remoteName, 0, 128);
	memset(raop_rtp_mirror->remoteDeviceId, 0, 128);
	if (remoteName != NULL) {
		strncpy(raop_rtp_mirror->remoteName, remoteName, min(128, strlen(remoteName)));
	}
	if (remoteDeviceId != NULL) {
		strncpy(raop_rtp_mirror->remoteDeviceId, remoteDeviceId, min(128, strlen(remoteDeviceId)));
	}

    raop_rtp_mirror->running = 0;
    raop_rtp_mirror->joined = 1;
    raop_rtp_mirror->flush = NO_FLUSH;

    MUTEX_CREATE(raop_rtp_mirror->run_mutex);
    MUTEX_CREATE(raop_rtp_mirror->time_mutex);
    COND_CREATE(raop_rtp_mirror->time_cond);
    return raop_rtp_mirror;
}

void
raop_rtp_init_mirror_aes(raop_rtp_mirror_t *raop_rtp_mirror, uint64_t streamConnectionID)
{
    mirror_buffer_init_aes(raop_rtp_mirror->buffer, streamConnectionID);
}

/**
 * ntp
 */
static THREAD_RETVAL
raop_rtp_mirror_thread_time(void *arg)
{
    raop_rtp_mirror_t *raop_rtp_mirror = arg;
    assert(raop_rtp_mirror);
    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    unsigned char packet[128];
    unsigned int packetlen;
    int first = 0;
    unsigned char time[48]={35,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    uint64_t base = now_us();
    uint64_t rec_pts = 0;
    uint64_t recv_failed_timeout_num = 10;
    while (1) {
        //MUTEX_LOCK(raop_rtp_mirror->run_mutex);
        if (!raop_rtp_mirror->running) {
            //MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);
            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "raop_rtp_mirror_thread_time exit");
            break;
        }
        //MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);
        uint64_t send_time = now_us() - base + rec_pts;

        byteutils_put_timeStamp(time, 40, send_time);
        logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "raop_rtp_mirror_thread_time send time 48 bytes, port = %d", raop_rtp_mirror->mirror_timing_rport);
        struct sockaddr_in *addr = (struct sockaddr_in *)&raop_rtp_mirror->remote_saddr;
        addr->sin_port = htons(raop_rtp_mirror->mirror_timing_rport);
        int sendlen = sendto(raop_rtp_mirror->mirror_time_sock, (char *)time, sizeof(time), 0, (struct sockaddr *) &raop_rtp_mirror->remote_saddr, raop_rtp_mirror->remote_saddr_len);
        logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "raop_rtp_mirror_thread_time sendlen = %d", sendlen);

        fd_set rfds;
        struct timeval tv;
        int nfds, ret;
        /* Set timeout value to 5ms */
        tv.tv_sec = 0;
        tv.tv_usec = 5000;

        /* Get the correct nfds value and set rfds */
        FD_ZERO(&rfds);
        FD_SET(raop_rtp_mirror->mirror_time_sock, &rfds);
        nfds = raop_rtp_mirror->mirror_time_sock + 1;
        ret = select(nfds, &rfds, NULL, NULL, &tv);
        logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "raop_rtp_mirror_thread_time ret = %d", ret);
        if (ret == 0) {
            /* Timeout happened */
            recv_failed_timeout_num--;
            sleepms(1000);
            logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "UDP raop_rtp_mirror_thread_time recv_failed_timeout_num = %d", recv_failed_timeout_num);
            if(recv_failed_timeout_num > 0)
                continue;
            else
            {
                break;
            }
        }
        recv_failed_timeout_num = 10;
        saddrlen = sizeof(saddr);
        packetlen = recvfrom(raop_rtp_mirror->mirror_time_sock, (char *)packet, sizeof(packet), 0,
                             (struct sockaddr *)&saddr, &saddrlen);
        logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "raop_rtp_mirror_thread_time receive time packetlen = %d", packetlen);
        // 16-24 The time when the system clock was last set or updated.
        uint64_t Reference_Timestamp = byteutils_read_timeStamp(packet, 16);
        // 24-32 Local time of the sender when the NTP request packet leaves the sender. T1
        uint64_t Origin_Timestamp = byteutils_read_timeStamp(packet, 24);
        // 32-40 Local time of the receiving end when the NTP request packet arrives at the receiving end. T2
        uint64_t Receive_Timestamp = byteutils_read_timeStamp(packet, 32);
        // 40-48 Transmit Timestamp: The local time of the responder when the response message leaves the responder. T3
        uint64_t Transmit_Timestamp = byteutils_read_timeStamp(packet, 40);

        // FIXME: Let's write this simply.
        rec_pts = Receive_Timestamp;

        if (first == 0) {
            first++;
        } else {
            struct timeval now;
            struct timespec outtime;
#ifndef WIN32
            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "raop_rtp_mirror->time_mutex");
            MUTEX_LOCK(raop_rtp_mirror->time_mutex);
#endif // !WIN32
            gettimeofday(&now, NULL);
            outtime.tv_sec = now.tv_sec + 3;
            outtime.tv_nsec = now.tv_usec * 1000;
            int ret = pthread_cond_timedwait(&raop_rtp_mirror->time_cond, &raop_rtp_mirror->time_mutex, &outtime);
#ifndef WIN32
            MUTEX_UNLOCK(raop_rtp_mirror->time_mutex);
#endif // !WIN32
            //sleepms(3000);
        }
    }
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Exiting UDP raop_rtp_mirror_thread_time thread");
    return 0;
}
//#define DUMP_H264

static THREAD_RETVAL
raop_exception_thread(void* arg)
{
    raop_rtp_mirror_t* raop_rtp_mirror = arg;
    raop_rtp_mirror_stop(raop_rtp_mirror);
    return 0;
}

#define RAOP_PACKET_LEN 32768

/**
 * Mirror
 */
static THREAD_RETVAL
raop_rtp_mirror_thread(void *arg)
{
    raop_rtp_mirror_t *raop_rtp_mirror = arg;
    int stream_fd = -1;
    unsigned char packet[128];
    memset(packet, 0 , 128);
    unsigned int readstart = 0;
    uint64_t pts_base = 0;
    uint64_t pts = 0;
    assert(raop_rtp_mirror);

    int exceptionExit = 0;
    int recv_failed_timeout_num = 1000;
#ifdef DUMP_H264
    FILE* file = fopen("demo.h264", "wb");
    FILE* file_source = fopen("demo.source", "wb");

    FILE* file_len = fopen("demo.len", "wb");
#endif
    while (1) {
        fd_set rfds;
        struct timeval tv;
        int nfds, ret;
        //MUTEX_LOCK(raop_rtp_mirror->run_mutex);
        if (!raop_rtp_mirror->running) {
            //MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);
            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "raop_rtp_mirror_thread exit");
            break;
        }
        //MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);
        /* Set timeout value to 5ms */
        tv.tv_sec = 0;
        tv.tv_usec = 5000;

        /* Get the correct nfds value and set rfds */
        FD_ZERO(&rfds);
        if (stream_fd == -1) {
            FD_SET(raop_rtp_mirror->mirror_data_sock, &rfds);
            nfds = raop_rtp_mirror->mirror_data_sock+1;
        } else {
            FD_SET(stream_fd, &rfds);
            nfds = stream_fd+1;
        }
        ret = select(nfds, &rfds, NULL, NULL, &tv);
        if (ret == 0) {
            /* Timeout happened */
            recv_failed_timeout_num--;
            logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "TCP raop_rtp_mirror_thread recv_failed_timeout_num = %d", recv_failed_timeout_num);
            if(recv_failed_timeout_num > 0)
                continue;
            else
            {
                logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Error in select");
                exceptionExit = 1;
                break;
            }
        } else if (ret == -1) {
            /* FIXME: Error happened */
            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Error in select");
            exceptionExit = 1;
            break;
        }
        recv_failed_timeout_num = 1000;
        if (stream_fd == -1 && FD_ISSET(raop_rtp_mirror->mirror_data_sock, &rfds)) {
            struct sockaddr_storage saddr;
            socklen_t saddrlen;

            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Accepting client");
            saddrlen = sizeof(saddr);
            stream_fd = accept(raop_rtp_mirror->mirror_data_sock, (struct sockaddr *)&saddr, &saddrlen);
            if (stream_fd == -1) {
                /* FIXME: Error happened */
                logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Error in accept %d %s", errno, strerror(errno));
                exceptionExit = 1;
                break;
            }
        }
        if (stream_fd != -1 && FD_ISSET(stream_fd, &rfds)) {
            // Packetlen initial 0
            ret = recv(stream_fd, packet + readstart, 4 - readstart, 0);
            if (ret == 0) {
                /* TCP socket closed */
                logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "TCP socket closed");
                exceptionExit = 1;
                break;
            } else if (ret == -1) {
                /* FIXME: Error happened */
                logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Error in recv");
                exceptionExit = 1;
                break;
            }
            readstart += ret;
            if (readstart < 4) {
                continue;
            }
            if ((packet[0] == 80 && packet[1] == 79 && packet[2] == 83 && packet[3] == 84) || (packet[0] == 71 && packet[1] == 69 && packet[2] == 84)) {
                // POST or GET
                logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "handle http data");
            } else {
                // Common data block
                do {
                    // Read the remaining 124 bytes
                    ret = recv(stream_fd, packet + readstart, 128 - readstart, 0);
                    readstart = readstart + ret;
                } while (readstart < 128);
                int payloadsize = byteutils_get_int(packet, 0);
                // FIXME: The calculation method here needs to be confirmed again.
                short payloadtype = (short) (byteutils_get_short(packet, 4) & 0xff);
                short payloadoption = byteutils_get_short(packet, 6);

                // Processing content data
                if (payloadtype == 0) {
                    uint64_t payloadntp = byteutils_get_long(packet, 8);
                    // Reading time
                    if (pts_base == 0) {
                        pts_base = ntptopts(payloadntp);
                    } else {
                        pts =  ntptopts(payloadntp) - pts_base;
                    }
                    // Here is the encrypted data
                    unsigned char* payload_in = malloc(payloadsize);
                    unsigned char* payload = malloc(payloadsize);
                    readstart = 0;
                    do {
                        // Payload data
                        ret = recv(stream_fd, payload_in + readstart, payloadsize - readstart, 0);
                        readstart = readstart + ret;
                    } while (readstart < payloadsize);
                    //logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "readstart = %d", readstart);
#ifdef DUMP_H264
                    fwrite(payload_in, payloadsize, 1, file_source);
                    fwrite(&readstart, sizeof(readstart), 1, file_len);
#endif
                    // Decrypt data
                    mirror_buffer_decrypt(raop_rtp_mirror->buffer, payload_in, payload, payloadsize);
                    int nalu_size = 0;
                    int nalu_num = 0;
                    while (nalu_size < payloadsize) {
                        int nc_len = (payload[nalu_size + 0] << 24) | (payload[nalu_size + 1] << 16) | (payload[nalu_size + 2] << 8) | (payload[nalu_size + 3]);
                        if (nc_len > 0) {
                            payload[nalu_size + 0] = 0;
                            payload[nalu_size + 1] = 0;
                            payload[nalu_size + 2] = 0;
                            payload[nalu_size + 3] = 1;
                            //int nalutype = payload[4] & 0x1f;
                            //logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "nalutype = %d", nalutype);
                            nalu_size += nc_len + 4;
                            nalu_num++;
                        }
                    }
                    //logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "nalu_size = %d, payloadsize = %d nalu_num = %d", nalu_size, payloadsize, nalu_num);

                    // Write file
#ifdef DUMP_H264
                    fwrite(payload, payloadsize, 1, file);
#endif
                    h264_decode_struct h264_data;
                    h264_data.data_len = payloadsize;
                    h264_data.data = payload;
                    h264_data.frame_type = 1;
                    h264_data.pts = pts;
                    raop_rtp_mirror->callbacks.video_process(raop_rtp_mirror->callbacks.cls, &h264_data, raop_rtp_mirror->remoteName, raop_rtp_mirror->remoteDeviceId);
                    free(payload_in);
                    free(payload);
                } else if ((payloadtype & 255) == 1) {
                    float mWidthSource = byteutils_get_float(packet, 40);
                    float mHeightSource = byteutils_get_float(packet, 44);
                    float mWidth = byteutils_get_float(packet, 56);
                    float mHeight =byteutils_get_float(packet, 60);
                    logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "mWidthSource = %f mHeightSource = %f mWidth = %f mHeight = %f", mWidthSource, mHeightSource, mWidth, mHeight);
                    /*int mRotateMode = 0;

                    int p = payloadtype >> 8;
                    if (p == 4) {
                        mRotateMode = 1;
                    } else if (p == 7) {
                        mRotateMode = 3;
                    } else if (p != 0) {
                        mRotateMode = 2;
                    }*/

                    // sps_pps This piece of data is not encrypted
                    unsigned char* payload = malloc(payloadsize);
                    readstart = 0;
                    do {
                        // Payload data
                        ret = recv(stream_fd, payload + readstart, payloadsize - readstart, 0);
                        readstart = readstart + ret;
                    } while (readstart < payloadsize);
                    h264codec_t h264;
                    h264.version = payload[0];
                    h264.profile_high = payload[1];
                    h264.compatibility = payload[2];
                    h264.level = payload[3];
                    h264.reserved6andNAL = payload[4];
                    h264.reserved3andSPS = payload[5];
                    h264.lengthofSPS = (short) (((payload[6] & 255) << 8) + (payload[7] & 255));
                    logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "lengthofSPS = %d", h264.lengthofSPS);
                    h264.sequence = malloc(h264.lengthofSPS);
                    memcpy(h264.sequence, payload + 8, h264.lengthofSPS);
                    h264.numberOfPPS = payload[h264.lengthofSPS + 8];
                    h264.lengthofPPS = (short) (((payload[h264.lengthofSPS + 9] & 2040) + payload[h264.lengthofSPS + 10]) & 255);
                    h264.picture_parameter_set = malloc(h264.lengthofPPS);
                    logger_log(raop_rtp_mirror->logger, LOGGER_DEBUG, "lengthofPPS = %d", h264.lengthofPPS);
                    memcpy(h264.picture_parameter_set, payload + h264.lengthofSPS + 11, h264.lengthofPPS);
                    if (h264.lengthofSPS + h264.lengthofPPS < 102400) {
                        // Copy spspps
                        int sps_pps_len = (h264.lengthofSPS + h264.lengthofPPS) + 8;
                        unsigned char* sps_pps = malloc(sps_pps_len);
                        sps_pps[0] = 0;
                        sps_pps[1] = 0;
                        sps_pps[2] = 0;
                        sps_pps[3] = 1;
                        memcpy(sps_pps + 4, h264.sequence, h264.lengthofSPS);
                        sps_pps[h264.lengthofSPS + 4] = 0;
                        sps_pps[h264.lengthofSPS + 5] = 0;
                        sps_pps[h264.lengthofSPS + 6] = 0;
                        sps_pps[h264.lengthofSPS + 7] = 1;
                        memcpy(sps_pps + h264.lengthofSPS + 8, h264.picture_parameter_set, h264.lengthofPPS);
#ifdef DUMP_H264
                        fwrite(sps_pps, sps_pps_len, 1, file);
#endif
                        h264_decode_struct h264_data;
                        h264_data.data_len = sps_pps_len;
                        h264_data.data = sps_pps;
                        h264_data.frame_type = 0;
                        h264_data.pts = 0;
                        raop_rtp_mirror->callbacks.video_process(raop_rtp_mirror->callbacks.cls, &h264_data, raop_rtp_mirror->remoteName, raop_rtp_mirror->remoteDeviceId);
                        free(sps_pps);
                    }
                    free(payload);
                    free(h264.picture_parameter_set);
                    free(h264.sequence);
                } else if (payloadtype == (short) 2) {
                    readstart = 0;
                    if (payloadsize > 0) {
                        unsigned char* payload_in = malloc(payloadsize);
                        do {
                            ret = recv(stream_fd, payload_in + readstart, payloadsize - readstart, 0);
                            readstart = readstart + ret;
                        } while (readstart < payloadsize);
						free(payload_in);
                    }
                } else if (payloadtype == (short) 4) {
                    readstart = 0;
                    if (payloadsize > 0) {
                        unsigned char* payload_in = malloc(payloadsize);
                        do {
                            ret = recv(stream_fd, payload_in + readstart, payloadsize - readstart, 0);
                            readstart = readstart + ret;
                        } while (readstart < payloadsize);
						free(payload_in);
                    }
                } else {
                    readstart = 0;
                    if (payloadsize > 0) {
                        unsigned char* payload_in = malloc(payloadsize);
                        do {
                            ret = recv(stream_fd, payload_in + readstart, payloadsize - readstart, 0);
                            readstart = readstart + ret;
                        } while (readstart < payloadsize);
                        free(payload_in);
                    }
                }
            }
            memset(packet, 0 , 128);
            readstart = 0;
        }
    }

    /* Close the stream file descriptor */
    if (stream_fd != -1) {
        closesocket(stream_fd);
    }
    if (exceptionExit) {
        if (raop_rtp_mirror->thread_exit_exception != NULL) {
            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Exiting exception thread[1]");
            THREAD_JOIN(raop_rtp_mirror->thread_exit_exception);
            raop_rtp_mirror->thread_exit_exception = NULL;
            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Exception thread exit[1]");
        }
        THREAD_CREATE(raop_rtp_mirror->thread_exit_exception, raop_exception_thread, raop_rtp_mirror);
    }
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Exiting TCP raop_rtp_mirror_thread thread");
#ifdef DUMP_H264
    fclose(file);
    fclose(file_source);
    fclose(file_len);
#endif
    return 0;
}

void
raop_rtp_start_mirror(raop_rtp_mirror_t *raop_rtp_mirror, int use_udp, unsigned short mirror_timing_rport, unsigned short * mirror_timing_lport,
                      unsigned short *mirror_data_lport)
{
    int use_ipv6 = 0;

    assert(raop_rtp_mirror);
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "raop_rtp_mirror->run_mutex2");
    MUTEX_LOCK(raop_rtp_mirror->run_mutex);
    if (raop_rtp_mirror->running || !raop_rtp_mirror->joined) {
        MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);
        return;
    }

    //raop_rtp_mirror->mirror_timing_rport = mirror_timing_rport;
    if (raop_rtp_mirror->remote_saddr.ss_family == AF_INET6) {
        use_ipv6 = 1;
    }
    use_ipv6 = 0;
    if (raop_rtp_init_mirror_sockets(raop_rtp_mirror, use_ipv6) < 0) {
        logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Initializing sockets failed");
        MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);
        return;
    }
    if (mirror_timing_lport) *mirror_timing_lport = raop_rtp_mirror->mirror_timing_lport;
    if (mirror_data_lport) *mirror_data_lport = raop_rtp_mirror->mirror_data_lport;

    /* Create the thread and initialize running values */
    raop_rtp_mirror->running = 1;
    raop_rtp_mirror->joined = 0;
    raop_rtp_mirror->run_mutex_destroyed = 0;
    raop_rtp_mirror->time_mutex_destroyed = 0;
    raop_rtp_mirror->time_cond_destroyed = 0;
    if (raop_rtp_mirror->callbacks.connected != NULL) {
        raop_rtp_mirror->callbacks.connected(raop_rtp_mirror->callbacks.cls, raop_rtp_mirror->remoteName, raop_rtp_mirror->remoteDeviceId);
    }

    THREAD_CREATE(raop_rtp_mirror->thread_mirror, raop_rtp_mirror_thread, raop_rtp_mirror);
    THREAD_CREATE(raop_rtp_mirror->thread_time, raop_rtp_mirror_thread_time, raop_rtp_mirror);
    MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);
}

void raop_rtp_mirror_stop(raop_rtp_mirror_t *raop_rtp_mirror) {
    assert(raop_rtp_mirror);
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Stopping raop rtp mirror");

    /* Check that we are running and thread is not
     * joined (should never be while still running) */
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "raop_rtp_mirror->run_mutex1");
    MUTEX_LOCK(raop_rtp_mirror->run_mutex);
    if (!raop_rtp_mirror->running || raop_rtp_mirror->joined) {
        MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);
        logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Raop rtp mirror stopped[1]");
        return;
    }
    raop_rtp_mirror->running = 0;
    MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);

    if (raop_rtp_mirror->mirror_data_sock != -1) {
        closesocket(raop_rtp_mirror->mirror_data_sock);
        raop_rtp_mirror->mirror_data_sock = -1;
    }
    if (raop_rtp_mirror->mirror_time_sock != -1) {
        closesocket(raop_rtp_mirror->mirror_time_sock);
        raop_rtp_mirror->mirror_time_sock = -1;
    }
    /* Join the thread */
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Join mirror thread");
    THREAD_JOIN(raop_rtp_mirror->thread_mirror);

#ifndef WIN32
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "raop_rtp_mirror->time_mutex1");
    if(raop_rtp_mirror->time_mutex_destroyed == 0)
        MUTEX_LOCK(raop_rtp_mirror->time_mutex);
#endif // !WIN32
    if(raop_rtp_mirror->time_cond_destroyed == 0)
        COND_SIGNAL(raop_rtp_mirror->time_cond);
#ifndef WIN32
    if(raop_rtp_mirror->time_mutex_destroyed == 0)
        MUTEX_UNLOCK(raop_rtp_mirror->time_mutex);
#endif // !WIN32
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Join mirror time thread");
    THREAD_JOIN(raop_rtp_mirror->thread_time);

    /* Mark thread as joined */
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "raop_rtp_mirror->run_mutex");
    if(raop_rtp_mirror->run_mutex_destroyed == 0)
        MUTEX_LOCK(raop_rtp_mirror->run_mutex);
    raop_rtp_mirror->joined = 1;
    if(raop_rtp_mirror->run_mutex_destroyed == 0)
        MUTEX_UNLOCK(raop_rtp_mirror->run_mutex);

    if (raop_rtp_mirror->callbacks.disconnected != NULL) {
        raop_rtp_mirror->callbacks.disconnected(raop_rtp_mirror->callbacks.cls, raop_rtp_mirror->remoteName, raop_rtp_mirror->remoteDeviceId);
    }
    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Raop rtp mirror stopped");
}

void raop_rtp_mirror_destroy(raop_rtp_mirror_t *raop_rtp_mirror) {
    if (raop_rtp_mirror) {
        raop_rtp_mirror_stop(raop_rtp_mirror);
        raop_rtp_mirror->run_mutex_destroyed = 1;
        MUTEX_DESTROY(raop_rtp_mirror->run_mutex);
        logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "MUTEX1_DESTROY");
        raop_rtp_mirror->time_mutex_destroyed = 1;
        MUTEX_DESTROY(raop_rtp_mirror->time_mutex);
        logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "MUTEX2_DESTROY");
        raop_rtp_mirror->time_cond_destroyed = 1;
        COND_DESTROY(raop_rtp_mirror->time_cond);
        logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "COND_DESTROY");
        mirror_buffer_destroy(raop_rtp_mirror->buffer);

        if (raop_rtp_mirror->thread_exit_exception) {
            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Exiting exception thread");
            THREAD_JOIN(raop_rtp_mirror->thread_exit_exception);
            raop_rtp_mirror->thread_exit_exception = NULL;
            logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Exception thread exit");
        }

        free(raop_rtp_mirror);
    }
}

static int
raop_rtp_init_mirror_sockets(raop_rtp_mirror_t *raop_rtp_mirror, int use_ipv6)
{
    int dsock = -1, tsock = -1;
    unsigned short tport = 0, dport = 0;

    assert(raop_rtp_mirror);

    dsock = netutils_init_socket(&dport, use_ipv6, 0);
    tsock = netutils_init_socket(&tport, use_ipv6, 1);
    if (dsock == -1 || tsock == -1) {
        goto sockets_cleanup;
    }

    /* Listen to the data socket if using TCP */
    if (listen(dsock, 1) < 0)
        goto sockets_cleanup;


    /* Set socket descriptors */
    raop_rtp_mirror->mirror_data_sock = dsock;
    raop_rtp_mirror->mirror_time_sock = tsock;

    /* Set port values */
    raop_rtp_mirror->mirror_data_lport = dport;
    raop_rtp_mirror->mirror_timing_lport = tport;

    logger_log(raop_rtp_mirror->logger, LOGGER_INFO, "Mirror data port: %d, timing port: ", dport, tport);

    return 0;

    sockets_cleanup:
    if (tsock != -1) closesocket(tsock);
    if (dsock != -1) closesocket(dsock);
    return -1;
}