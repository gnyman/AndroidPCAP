#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>
#include <errno.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PACKET_LEN 8192

// CACE PPI headers
typedef struct {
	uint8_t pph_version;
	uint8_t pph_flags;
	uint16_t pph_len;
	uint32_t pph_dlt;
} __attribute__((packed)) ppi_packet_header;

// CACE PPI field header
typedef struct {
	uint16_t pfh_type; /* Type */
	uint16_t pfh_datalen; /* Length of data */
} __attribute__((packed)) ppi_fieldheader_t;

typedef struct {
	pcap_t *dumpfile;
	pcap_dumper_t *dumper;
	unsigned int dlt;
} pcap_jni_state;

typedef struct {
	uint64_t tsf_timer;
	uint16_t flags;
	uint16_t rate;
	uint16_t freq_mhz;
	uint16_t chan_flags;
	uint8_t fhss_hopset;
	uint8_t fhss_pattern;
	int8_t signal_dbm;
	int8_t noise_dbm;
} __attribute__((packed)) ppi_80211_common;

JNIEXPORT jboolean JNICALL Java_net_kismetwireless_android_pcapcapture_PcapLogger_openPcap(JNIEnv *env, jobject this, jstring file, 
																		unsigned int dlt) {
	jfieldID pcap_state_field;
	jmethodID pcap_init;
	jclass class_ioex, class_pcaplogger;

	pcap_jni_state *state;
	jobject stateobj;

	jboolean isCopy;
	char *filepath = NULL;

	char buf[1024];

	uint16_t ppi_len;

	// Find the pcaplogger class (this)
	class_pcaplogger = (*env)->FindClass(env, "net/kismetwireless/android/pcapcapture/PcapLogger");
	if (class_pcaplogger == NULL)
		return 0;

	// Find the pcap state field
	pcap_state_field = (*env)->GetFieldID(env, class_pcaplogger, "pcap_state", "Ljava/nio/ByteBuffer;");
	if (pcap_state_field == NULL)
		return 0;

	// Find the classes for io exception and filedescriptor in java
	class_ioex = (*env)->FindClass(env, "java/io/IOException");
	if (class_ioex == NULL)
		return 0;

	state = (pcap_jni_state *) malloc(sizeof(pcap_jni_state));

	state->dumpfile = pcap_open_dead(dlt, MAX_PACKET_LEN);
	if (state->dumpfile == NULL) {
		snprintf(buf, 1024, "pcap_open_dead: %s", strerror(errno));
		free(state);
		(*env)->ThrowNew(env, class_ioex, buf);
		return 0;
	}

	filepath = (char *) (*env)->GetStringUTFChars(env, file, &isCopy);

	state->dumper = pcap_dump_open(state->dumpfile, filepath);
	if (state->dumper == NULL) {
		snprintf(buf, 1024, "pcap_dump_open: %s", strerror(errno));
		(*env)->ReleaseStringUTFChars(env, file, filepath);
		pcap_close(state->dumpfile);
		free(state);
		(*env)->ThrowNew(env, class_ioex, buf);
		return 0;
	}

	state->dlt = dlt;

	(*env)->ReleaseStringUTFChars(env, file, filepath);

	stateobj = (*env)->NewDirectByteBuffer(env, (void *) state, sizeof(pcap_jni_state));

	(*env)->SetObjectField(env, this, pcap_state_field, stateobj);

	return 1;
}

JNIEXPORT void JNICALL Java_net_kismetwireless_android_pcapcapture_PcapLogger_closePcap(JNIEnv *env, jobject this) {
	jfieldID pcap_state_field;
	jclass class_pcaplogger;

	pcap_jni_state *state;
	jobject stateobj;

	// Find the pcaplogger class (this)
	class_pcaplogger = (*env)->FindClass(env, "net/kismetwireless/android/pcapcapture/PcapLogger");
	if (class_pcaplogger == NULL)
		return;

	// Find the pcap state field
	pcap_state_field = (*env)->GetFieldID(env, class_pcaplogger, "pcap_state", "Ljava/nio/ByteBuffer;");
	if (pcap_state_field == NULL)
		return;


	stateobj = (*env)->GetObjectField(env, this, pcap_state_field);

	if (stateobj == NULL)
		return;

	state = (pcap_jni_state *) (*env)->GetDirectBufferAddress(env, stateobj);

	pcap_dump_flush(state->dumper);
	pcap_dump_close(state->dumper);
	pcap_close(state->dumpfile);

	free(state);

	(*env)->SetObjectField(env, this, pcap_state_field, NULL);

	return;
}

JNIEXPORT jboolean JNICALL Java_net_kismetwireless_android_pcapcapture_PcapLogger_logPacket(JNIEnv *env, jobject this,
																	  jobject packet) {
	jfieldID pcap_state_field, packet_bytes_field, packet_dlt_field;
	jclass class_ioex, class_pcaplogger, class_packet;

	pcap_jni_state *state;
	jobject stateobj;

	int packet_dlt;
	jbyteArray packet_bytes;
	jbyte *bytebuffer;
	jboolean isCopy;
	jsize bytebufferlength;

	char buf[1024];

	struct pcap_pkthdr wh;
	struct timeval ts;

	// Find the classes for io exception and filedescriptor in java
	class_ioex = (*env)->FindClass(env, "java/io/IOException");
	if (class_ioex == NULL)
		return 0;

	// Find the pcaplogger class (this)
	class_pcaplogger = (*env)->FindClass(env, "net/kismetwireless/android/pcapcapture/PcapLogger");
	if (class_pcaplogger == NULL)
		return 0;

	// Find the pcap state field
	pcap_state_field = (*env)->GetFieldID(env, class_pcaplogger, "pcap_state", "Ljava/nio/ByteBuffer;");
	if (pcap_state_field == NULL)
		return 0;

	// Find the packet class
	class_packet = (*env)->FindClass(env, "net/kismetwireless/android/pcapcapture/Packet");
	if (class_packet == NULL)
		return 0;

	packet_bytes_field = (*env)->GetFieldID(env, class_packet, "bytes", "[B");
	if (packet_bytes_field == NULL)
		return 0;

	packet_dlt_field = (*env)->GetFieldID(env, class_packet, "dlt", "I");
	if (packet_dlt_field == NULL)
		return 0;

	stateobj = (*env)->GetObjectField(env, this, pcap_state_field);

	if (stateobj == NULL) {
		snprintf(buf, 1024, "pcap log not open");
		(*env)->ThrowNew(env, class_ioex, buf);
		return 0;
	}

	state = (pcap_jni_state *) (*env)->GetDirectBufferAddress(env, stateobj);

	packet_dlt = (*env)->GetIntField(env, packet, packet_dlt_field);
	packet_bytes = (jbyteArray) (*env)->GetObjectField(env, packet, packet_bytes_field);

	bytebuffer = (*env)->GetByteArrayElements(env, packet_bytes, &isCopy);
	bytebufferlength = (*env)->GetArrayLength(env, packet_bytes);

	gettimeofday(&ts, NULL);

	wh.ts.tv_sec = ts.tv_sec;
	wh.ts.tv_usec = ts.tv_usec;
	wh.caplen = wh.len = bytebufferlength;

	pcap_dump((u_char *) state->dumper, &wh, bytebuffer);

	(*env)->ReleaseByteArrayElements(env, packet_bytes, bytebuffer, 0);

	return;
}

JNIEXPORT jboolean JNICALL Java_net_kismetwireless_android_pcapcapture_PcapLogger_logPPIPacket(JNIEnv *env, jobject this,
																	  jobject packet) {
	jfieldID pcap_state_field, packet_bytes_field, packet_dlt_field, packet_signal_field;
	jclass class_ioex, class_pcaplogger, class_packet;

	pcap_jni_state *state;
	jobject stateobj;

	int packet_dlt;
	int packet_signal;
	jbyteArray packet_bytes;
	jbyte *bytebuffer;
	jboolean isCopy;
	jsize bytebufferlength;

	char buf[1024];

	struct pcap_pkthdr wh;
	struct timeval ts;

	// PPI mangling
	uint8_t *logblob;
	ppi_packet_header *ppih;
	ppi_fieldheader_t * ppifh;
	ppi_80211_common * ppif11c;

	// Find the classes for io exception and filedescriptor in java
	class_ioex = (*env)->FindClass(env, "java/io/IOException");
	if (class_ioex == NULL)
		return 0;

	// Find the pcaplogger class (this)
	class_pcaplogger = (*env)->FindClass(env, "net/kismetwireless/android/pcapcapture/PcapLogger");
	if (class_pcaplogger == NULL)
		return 0;

	// Find the pcap state field
	pcap_state_field = (*env)->GetFieldID(env, class_pcaplogger, "pcap_state", "Ljava/nio/ByteBuffer;");
	if (pcap_state_field == NULL)
		return 0;

	// Find the packet class
	class_packet = (*env)->FindClass(env, "net/kismetwireless/android/pcapcapture/Packet");
	if (class_packet == NULL)
		return 0;

	packet_bytes_field = (*env)->GetFieldID(env, class_packet, "bytes", "[B");
	if (packet_bytes_field == NULL)
		return 0;

	packet_dlt_field = (*env)->GetFieldID(env, class_packet, "dlt", "I");
	if (packet_dlt_field == NULL)
		return 0;

	packet_signal_field = (*env)->GetFieldID(env, class_packet, "signal", "I");
	if (packet_signal_field == NULL)
		return 0;

	stateobj = (*env)->GetObjectField(env, this, pcap_state_field);

	if (stateobj == NULL) {
		snprintf(buf, 1024, "pcap log not open");
		(*env)->ThrowNew(env, class_ioex, buf);
		return 0;
	}

	state = (pcap_jni_state *) (*env)->GetDirectBufferAddress(env, stateobj);

	packet_dlt = (*env)->GetIntField(env, packet, packet_dlt_field);
	packet_bytes = (jbyteArray) (*env)->GetObjectField(env, packet, packet_bytes_field);
	packet_signal = (*env)->GetIntField(env, packet, packet_signal_field);

	bytebuffer = (*env)->GetByteArrayElements(env, packet_bytes, &isCopy);
	bytebufferlength = (*env)->GetArrayLength(env, packet_bytes);

	logblob = (uint8_t *) calloc(1, bytebufferlength + sizeof(ppi_packet_header) + sizeof(ppi_fieldheader_t) + sizeof(ppi_80211_common));
	ppih = (ppi_packet_header *) logblob;

	ppih->pph_version = 0;
	ppih->pph_flags = 0;
	ppih->pph_len = htole16(sizeof(ppi_packet_header) + sizeof(ppi_fieldheader_t) + sizeof(ppi_80211_common));
	ppih->pph_dlt = htole32(packet_dlt);
	
	ppifh = (ppi_fieldheader_t *) (logblob+sizeof(ppi_packet_header));
	ppifh->pfh_type = htole16(2);
	ppifh->pfh_datalen = htole16(sizeof(ppi_80211_common));

	ppif11c = (ppi_80211_common *) (logblob + sizeof(ppi_packet_header) + sizeof(ppi_fieldheader_t));
	ppif11c->signal_dbm = htole32(packet_signal);

	memcpy(logblob + sizeof(ppi_packet_header) + sizeof(ppi_fieldheader_t) + sizeof(ppi_80211_common) , bytebuffer, bytebufferlength);

	gettimeofday(&ts, NULL);

	wh.ts.tv_sec = ts.tv_sec;
	wh.ts.tv_usec = ts.tv_usec;
	wh.caplen = wh.len = bytebufferlength + sizeof(ppi_packet_header) + sizeof(ppi_fieldheader_t) + sizeof(ppi_80211_common);

	pcap_dump((u_char *) state->dumper, &wh, logblob);

	free(logblob);

	(*env)->ReleaseByteArrayElements(env, packet_bytes, bytebuffer, 0);

	return;
}

JNIEXPORT jint JNICALL Java_net_kismetwireless_android_pcapcapture_PcapHelper_countPcapFile(JNIEnv *env, jobject this,
																			jstring file, jint max) {
	jboolean isCopy;
	char *filepath = NULL;
	char buf[1024];

	jclass class_ioex;

	pcap_t *dumpfile;
	struct pcap_pkthdr ph;

	jint npackets = 0;

	// Find the classes for io exception and filedescriptor in java
	class_ioex = (*env)->FindClass(env, "java/io/IOException");
	if (class_ioex == NULL)
		return 0;

	filepath = (char *) (*env)->GetStringUTFChars(env, file, &isCopy);

	if ((dumpfile = pcap_open_offline(filepath, buf)) == NULL) {
		(*env)->ReleaseStringUTFChars(env, file, filepath);
		(*env)->ThrowNew(env, class_ioex, buf);
		return 0;
	}

	while (pcap_next(dumpfile, &ph) != NULL && npackets < max) 
		npackets++;

	pcap_close(dumpfile);

	(*env)->ReleaseStringUTFChars(env, file, filepath);

	return npackets;
}
