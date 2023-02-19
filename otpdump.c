// dump the TOTP secrets from a Google Authenticator export QR code:
// zbar[img|cam] --raw |<this>
// depends on base64 & base32 programs
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

static FILE* _dbg;

void gdump(unsigned int tag, ...) {
	va_list ap;
	va_start(ap, tag);
	// print known tags
	switch (tag) {
	case 0x0a:		// field 1 bytes => secret
	{
		unsigned char* buf = va_arg(ap, unsigned char*);
		size_t len = va_arg(ap, size_t);
		printf("secret: ");
		fflush(stdout);
		FILE* bout = popen("base32 --wrap=0", "w");
		fwrite(buf, len, 1, bout);
		pclose(bout);
		printf("\n");
		break;
	}
	case 0x12:		// field 2 bytes => name
	{
		char* buf = va_arg(ap, char*);
		size_t len = va_arg(ap, size_t);
		printf("name: %.*s\n", len, buf);
		break;
	}
	case 0x1a:		// field 3 bytes => issuer
	{
		char* buf = va_arg(ap, char*);
		size_t len = va_arg(ap, size_t);
		printf("issuer: %.*s\n", len, buf);
		break;
	}
	case 0x10:		// field 2 varint => version
	{
		unsigned int ver = va_arg(ap, unsigned int);
		printf("version: %d\n", ver);
		break;
	}
	}
	va_end(ap);
}

size_t varint(unsigned char* buf, size_t len, unsigned int* out) {
	// decode a varint
	size_t pos = 0;
	int tbit = 0;
	unsigned int mul = 1;
	*out = 0;
	do {
		tbit = buf[pos] & 0x80;
		unsigned char val = buf[pos] & 0x7f;
		*out += (unsigned int)val * mul;
		pos += 1;
		mul *= 128;
	} while (tbit && pos<len);
	return pos;
}

size_t pdec(unsigned char* buf, size_t len) {
	// always start by decoding the field/type tag varint
	size_t pos = 0;
	unsigned int tag;
	pos += varint(buf, len, &tag);
	unsigned char fld, type;
	fld = tag >> 3;
	type= tag & 7;
	if (_dbg) fprintf(_dbg, "<F:%d,T:%d>=", fld, type);
	// decode as appropriate..
	switch (type) {
	case 0:		// VARINT value
	{
		unsigned int val;
		pos += varint(buf+pos, len-pos, &val);
		if (_dbg) fprintf(_dbg, "<V:%d/0x%x>", val, val);
		gdump(tag, val);
		break;
	}
	case 2:		// LEN value
	{
		unsigned int vl;
		pos += varint(buf+pos, len-pos, &vl);
		// sanity check - does this fit?
		if (pos+vl>len) {
			if (_dbg) fprintf(_dbg, "<L:exceeds buffer len>");
			break;
		}
		if (_dbg) fprintf(_dbg, "<L:%d[", vl);
		// heuristic hack - see if the next varint is a valid type and field id 1..
		unsigned int t;
		size_t d = varint(buf+pos, len-pos, &t);
		if (d>0 && (t&7)<6 && (t>>3)==1) {
			// yep - assume submessage and recurse..
			size_t vp = 0;
			while (vp<vl) {
				vp += pdec(buf+pos+vp, len-pos-vp);
			}
			pos += vp;
		} else {
			// nope - assume byte string and dump..
			for (size_t o=0; o<vl; o++)
				if (_dbg) fprintf(_dbg, "%s%02x", o>0?" ":"", buf[pos+o]);
			gdump(tag, buf+pos, vl);
			pos += vl;
		}
		if (_dbg) fprintf(_dbg, "]>");
		break;
	}
	case 1:		// I64
	case 3:		// SGROUP
	case 4:		// EGROUP
	case 5:		// I32
	default:	// ??
		if (_dbg) fprintf(_dbg, "<unsupported>");
		break;
	}
	return pos;
}

int main(int argc, char** argv) {
	char buf[8192];
	if (argc > 1)
		_dbg = stderr;
	while (fgets(buf, sizeof(buf), stdin)) {
		size_t len = strlen(buf);
		// remove trailing newline if any
		if ('\n'==buf[len-1]) {
			buf[len-1] = 0;
			len -= 1;
		}
		// replace URL encodings..
		for (size_t i=0; i<len; i++) {
			if ('%'==buf[i]) {
				unsigned int t;
				sscanf(buf+i+1, "%2x", &t);
				buf[i] = (char)t;
				for (size_t j=i+1; j<len-2; j++) buf[j] = buf[j+2];
				len -= 2;
				buf[len] = 0;
			}
		}
		// find start of base64 data
		size_t i=0;
		while ('='!=buf[i] && i<len) i++;
		i++;
		// decode to protobuf3
		char* cmd=NULL;
		asprintf(&cmd, "echo %s |base64 -d", buf+i);
		FILE* bin=popen(cmd, "r");
		free(cmd);
		unsigned char pb3[8192];
		size_t pl=fread(pb3, 1, sizeof(pb3), bin);
		pclose(bin);
		// decode protobuf3..
		if (_dbg) fprintf(_dbg, "protobuf size: %d bytes\n", pl);
		size_t use = 0;
		while (use<pl) {
			use += pdec(pb3+use, pl-use);
			printf("\n");
		}
	}
	return 0;
}

