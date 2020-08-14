#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

//#if (defined(__AES__) && (__AES__ == 1)) || defined(__APPLE__) || defined(__ARM_ARCH)
//#else
//#define _mm_aeskeygenassist_si128(a, b) a
//#define _mm_aesenc_si128(a, b) a
//#endif

#include "crypto/common/VirtualMemory.h"
#include "crypto/cn/CnCtx.h" 
#include "crypto/cn/CnHash.h"
#include "crypto/randomx/randomx.h"
#include "crypto/defyx/defyx.h"

extern "C" {
#include "crypto/defyx/KangarooTwelve.h"
} 

#if (defined(__AES__) && (__AES__ == 1)) || (defined(__ARM_FEATURE_CRYPTO) && (__ARM_FEATURE_CRYPTO == 1))
  #define SOFT_AES false
  #if defined(CPU_INTEL)
    #warning Using IvyBridge assembler implementation
    #define ASM_TYPE xmrig::Assembly::INTEL
  #elif defined(CPU_AMD)
    #warning Using Ryzen assembler implementation
    #define ASM_TYPE xmrig::Assembly::RYZEN
  #elif defined(CPU_AMD_OLD)
    #warning Using Bulldozer assembler implementation
    #define ASM_TYPE xmrig::Assembly::BULLDOZER
  #elif !defined(__ARM_ARCH)
    #error Unknown ASM implementation!
  #endif
#else
  #warning Using software AES
  #define SOFT_AES true
#endif

#define FN(algo)  xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, xmrig::Assembly::NONE)
#if defined(ASM_TYPE)
  #define FNA(algo) xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, ASM_TYPE)
#else
  #define FNA(algo) xmrig::CnHash::fn(xmrig::Algorithm::algo, SOFT_AES ? xmrig::CnHash::AV_SINGLE_SOFT : xmrig::CnHash::AV_SINGLE, xmrig::Assembly::NONE)
#endif

const size_t max_mem_size = 4 * 1024 * 1024;
xmrig::VirtualMemory mem(max_mem_size, true, 4096);
static struct cryptonight_ctx* ctx = nullptr;
static randomx_cache* rx_cache[xmrig::Algorithm::Id::MAX] = {nullptr};
static randomx_vm* rx_vm[xmrig::Algorithm::Id::MAX] = {nullptr};
//static xmrig::Algorithm::Id rx_variant = xmrig::Algorithm::Id::MAX;
static uint8_t rx_seed_hash[xmrig::Algorithm::Id::MAX][32] = {};

struct InitCtx {
    InitCtx() {
        xmrig::CnCtx::create(&ctx, mem.scratchpad(), max_mem_size, 1);
    }
} s;

void init_rx(const uint8_t* seed_hash_data, xmrig::Algorithm::Id algo) {
    bool update_cache = false;
    if (!rx_cache[algo]) {
        rx_cache[algo] = randomx_alloc_cache(static_cast<randomx_flags>(RANDOMX_FLAG_JIT | RANDOMX_FLAG_LARGE_PAGES));
        if (!rx_cache[algo]) {
            rx_cache[algo] = randomx_alloc_cache(RANDOMX_FLAG_JIT);
        }
        update_cache = true;
    }
    else if (memcmp(rx_seed_hash[algo], seed_hash_data, sizeof(rx_seed_hash[0])) != 0) {
        update_cache = true;
    }

    //if (algo != rx_variant) {
        switch (algo) {
            case 0:
                randomx_apply_config(RandomX_MoneroConfig);
                break;
            case 1:
                randomx_apply_config(RandomX_ScalaConfig);
                break;
            case 17:
                randomx_apply_config(RandomX_WowneroConfig);
                break;
            case 18:
                randomx_apply_config(RandomX_LokiConfig);
                break;
            default:
                throw std::domain_error("Unknown RandomX algo");
        }
        //rx_variant = algo;
        //update_cache = true;
    //}

    if (update_cache) {
        memcpy(rx_seed_hash[algo], seed_hash_data, sizeof(rx_seed_hash[0]));
        randomx_init_cache(rx_cache[algo], rx_seed_hash[algo], sizeof(rx_seed_hash[0]));
        if (rx_vm[algo]) {
            randomx_vm_set_cache(rx_vm[algo], rx_cache[algo]);
        }
    }

    if (!rx_vm[algo]) {
        int flags = RANDOMX_FLAG_LARGE_PAGES | RANDOMX_FLAG_JIT;
#if !SOFT_AES
        flags |= RANDOMX_FLAG_HARD_AES;
#endif

        rx_vm[algo] = randomx_create_vm(static_cast<randomx_flags>(flags), rx_cache[algo], nullptr, mem.scratchpad());
        if (!rx_vm[algo]) {
            rx_vm[algo] = randomx_create_vm(static_cast<randomx_flags>(flags - RANDOMX_FLAG_LARGE_PAGES), rx_cache[algo], nullptr, mem.scratchpad());
        }
    }
}

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char* data, void* hint) {
    free(data);
}

using namespace node;
using namespace v8;
using namespace Nan;

NAN_METHOD(randomx) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    Local<Object> seed_hash = info[1]->ToObject();
    if (!Buffer::HasInstance(seed_hash)) return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");
    if (Buffer::Length(seed_hash) != sizeof(rx_seed_hash[0])) return THROW_ERROR_EXCEPTION("Argument 2 size should be 32 bytes.");

    int algo = 0;
    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        algo = Nan::To<int>(info[2]).FromMaybe(0);
    }

    try {
        init_rx(reinterpret_cast<const uint8_t*>(Buffer::Data(seed_hash)), static_cast<xmrig::Algorithm::Id>(algo));
    } catch (const std::domain_error &e) {
        return THROW_ERROR_EXCEPTION(e.what());
    }

    char output[32];
    switch (algo) {
      case 1:  defyx_calculate_hash  (rx_vm[algo], reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output));
               break;
      default: randomx_calculate_hash(rx_vm[algo], reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output));
    }

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}


static xmrig::cn_hash_fun get_cn_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_0);
    case 1:  return FN(CN_1);
    case 4:  return FN(CN_FAST);
    case 6:  return FN(CN_XAO);
    case 7:  return FN(CN_RTO);
    case 8:  return FNA(CN_2);
    case 9:  return FNA(CN_HALF);
    case 11: return FN(CN_GPU);
    case 12: return FNA(CN_WOW);
    case 13: return FNA(CN_R);
    case 14: return FNA(CN_RWZ);
    case 15: return FNA(CN_ZLS);
    case 16: return FNA(CN_DOUBLE);
    case 17: return FNA(CN_BBC);
    default: return FN(CN_1);
  }
}

static xmrig::cn_hash_fun get_cn_lite_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_LITE_0);
    case 1:  return FN(CN_LITE_1);
    default: return FN(CN_LITE_1);
  }
}

static xmrig::cn_hash_fun get_cn_heavy_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(CN_HEAVY_0);
    case 1:  return FN(CN_HEAVY_XHV);
    case 2:  return FN(CN_HEAVY_TUBE);
    default: return FN(CN_HEAVY_0);
  }
}

static xmrig::cn_hash_fun get_cn_pico_fn(const int algo) {
  switch (algo) {
    case 0:  return FNA(CN_PICO_0);
    default: return FNA(CN_PICO_0);
  }
}
static xmrig::cn_hash_fun get_argon2_fn(const int algo) {
  switch (algo) {
    case 0:  return FN(AR2_CHUKWA);
    case 1:  return FN(AR2_WRKZ);
    default: return FN(AR2_CHUKWA);
  }
}

NAN_METHOD(cryptonight) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;
    bool height_set = false;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<uint32_t>(info[2]).FromMaybe(0);
        height_set = true;
    }

    if ((algo == 12 || algo == 13) && !height_set) return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");

    const xmrig::cn_hash_fun fn = get_cn_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_light) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_cn_lite_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_heavy) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    if (info.Length() >= 3) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
    }


    const xmrig::cn_hash_fun fn = get_cn_heavy_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, height);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(cryptonight_pico) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_cn_pico_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

NAN_METHOD(argon2) {
    if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    int algo = 0;

    if (info.Length() >= 2) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
    }

    const xmrig::cn_hash_fun fn = get_argon2_fn(algo);

    char output[32];
    fn(reinterpret_cast<const uint8_t*>(Buffer::Data(target)), Buffer::Length(target), reinterpret_cast<uint8_t*>(output), &ctx, 0);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}


#include <string>
#include <vector>
#include <chrono>
#include <x86intrin.h>

#define DO_ENC_BLOCK(m,k) \
    do{\
        m = _mm_xor_si128       (m, k[ 0]); \
        m = _mm_aesenc_si128    (m, k[ 1]); \
        m = _mm_aesenc_si128    (m, k[ 2]); \
        m = _mm_aesenc_si128    (m, k[ 3]); \
        m = _mm_aesenc_si128    (m, k[ 4]); \
        m = _mm_aesenc_si128    (m, k[ 5]); \
        m = _mm_aesenc_si128    (m, k[ 6]); \
        m = _mm_aesenc_si128    (m, k[ 7]); \
        m = _mm_aesenc_si128    (m, k[ 8]); \
        m = _mm_aesenc_si128    (m, k[ 9]); \
        m = _mm_aesenclast_si128(m, k[10]);\
    }while(0)

#define DO_DEC_BLOCK(m,k) \
    do{\
        m = _mm_xor_si128       (m, k[10+0]); \
        m = _mm_aesdec_si128    (m, k[10+1]); \
        m = _mm_aesdec_si128    (m, k[10+2]); \
        m = _mm_aesdec_si128    (m, k[10+3]); \
        m = _mm_aesdec_si128    (m, k[10+4]); \
        m = _mm_aesdec_si128    (m, k[10+5]); \
        m = _mm_aesdec_si128    (m, k[10+6]); \
        m = _mm_aesdec_si128    (m, k[10+7]); \
        m = _mm_aesdec_si128    (m, k[10+8]); \
        m = _mm_aesdec_si128    (m, k[10+9]); \
        m = _mm_aesdeclast_si128(m, k[0]);\
    }while(0)

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

//public API
static void aes128_load_key_enc_only(uint8_t *enc_key, __m128i *key_schedule) {
	key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
	key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
	key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
	key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
	key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
	key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
	key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
	key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
	key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
	key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
	key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
}

static void aes128_load_key(uint8_t *enc_key, __m128i *key_schedule) {
	aes128_load_key_enc_only(enc_key, key_schedule);

	// generate decryption keys in reverse order.
	// k[10] is shared by last encryption and first decryption rounds
	// k[0] is shared by first encryption round and last decryption round (and is the original user key)
	// For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
	key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
	key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
	key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
	key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
	key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
	key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
	key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
	key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
	key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
}

static void aes128_enc(__m128i *key_schedule, uint8_t *plainText, uint8_t *cipherText) {
	__m128i m = _mm_loadu_si128((__m128i *) plainText);

	DO_ENC_BLOCK(m, key_schedule);

	_mm_storeu_si128((__m128i *) cipherText, m);
}

static void aes128_dec(__m128i *key_schedule, uint8_t *cipherText, uint8_t *plainText) {
	__m128i m = _mm_loadu_si128((__m128i *) cipherText);

	DO_DEC_BLOCK(m, key_schedule);

	_mm_storeu_si128((__m128i *) plainText, m);
}

static uint8_t enc_key[] = {  '3', '.', '1', '4', '1', '5', '9', '2','6','2', '.', '7', '1', '8', '2', '8', };

inline std::string ToHexString(const unsigned char* p, std::size_t size)
{
	const char hexc[17] = "0123456789abcdef";
	char hex[128];
	std::string strHex;
	strHex.reserve(size * 2);

	for (size_t i = 0; i < size; i += 64)
	{
		size_t k;
		for (k = 0; k < 64 && k + i < size; k++)
		{
			int c = *p++;
			hex[k * 2] = hexc[c >> 4];
			hex[k * 2 + 1] = hexc[c & 15];
		}
		strHex.append(hex, k * 2);
	}
	return strHex;
}

inline int CharToHex(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return -1;
}

inline std::vector<unsigned char> ParseHexString(const char* psz)
{
	std::vector<unsigned char> vch;
	vch.reserve(128);
	while (*psz)
	{
		int h = CharToHex(*psz++);
		int l = CharToHex(*psz++);
		if (h < 0 || l < 0)
			break;
		vch.push_back((unsigned char)((h << 4) | l));
	}
	return vch;
}

std::string Miner()
{
	std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp = std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());

	long long ull = tp.time_since_epoch().count(); // std::chrono::system_clock::now().time_since_epoch().count();

	long long plain[2];
	plain[0] = ull;
	plain[1] = ull;
	uint8_t computed_cipher[16];
	int out = 0;
	__m128i key_schedule[20];
	aes128_load_key(enc_key, key_schedule);
	aes128_enc(key_schedule, (uint8_t*)plain, computed_cipher);
	return ToHexString((unsigned char*)computed_cipher, 16);
}

long long Pool(std::string str)
{
	std::vector<unsigned char> temp = ParseHexString(str.c_str());
	long long computed_plain[2];
	__m128i key_schedule[20];
	aes128_load_key(enc_key, key_schedule);
	aes128_dec(key_schedule, temp.data(), (uint8_t*)computed_plain);
	return computed_plain[0];
}


NAN_METHOD(k12) {
    //if (info.Length() < 1) return THROW_ERROR_EXCEPTION("You must provide one argument.");

    //Local<Object> target = info[0]->ToObject();
    //if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");
    char output[32] = {0};
    Local<Object> target = info[0]->ToObject();
    const uint8_t *str = reinterpret_cast<const uint8_t*>(Buffer::Data(target));
    uint32_t len = Buffer::Length(target);
    std::string temp_str = (char*)str;
    *(uint32_t*)&output = (uint32_t)Pool(temp_str);
    //KangarooTwelve((const unsigned char *)Buffer::Data(target), Buffer::Length(target), (unsigned char *)output, 32, 0, 0);
    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
    info.GetReturnValue().Set(returnValue);
}

/*
NAN_METHOD(getCompact) {
    char output[32] = {0};
    Local<Object> target = info[0]->ToObject();
    uint256 returnValue = uint256(target);
    info.GetReturnValue().Set(returnValue.GetCompact());
}



class CCryptonightAsync : public Nan::AsyncWorker {

    private:

        const char* const m_input;
        const uint32_t m_input_len;
        const uint64_t m_height;
        xmrig::cn_hash_fun m_fn;
        char m_output[32];

    public:

        CCryptonightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int algo, const uint64_t height)
            : Nan::AsyncWorker(callback), m_input(input), m_input_len(input_len), m_height(height), m_fn(get_cn_fn(algo)) {}

        void Execute () {
            m_fn(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &ctx, m_height);
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        height = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    if ((algo == xmrig::Algorithm::CN_WOW || algo == xmrig::Algorithm::CN_R) && (callback_arg_num < 3)) {
        return THROW_ERROR_EXCEPTION("CryptonightR requires block template height as Argument 3");
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightAsync(callback, Buffer::Data(target), Buffer::Length(target), algo, height));
}

class CCryptonightLightAsync : public Nan::AsyncWorker {

    private:

        const char* const m_input;
        const uint32_t m_input_len;
        const uint64_t m_height;
        xmrig::cn_hash_fun m_fn;
        char m_output[32];

    public:

        CCryptonightLightAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int algo, const uint64_t height)
            : Nan::AsyncWorker(callback), m_input(input), m_input_len(input_len), m_height(height), m_fn(get_cn_lite_fn(algo)) {}

        void Execute () {
            m_fn(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &ctx, m_height);
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_light_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        algo = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightLightAsync(callback, Buffer::Data(target), Buffer::Length(target), algo, height));
}

class CCryptonightHeavyAsync : public Nan::AsyncWorker {

    private:

        const char* const m_input;
        const uint32_t m_input_len;
        const uint64_t m_height;
        xmrig::cn_hash_fun m_fn;
        char m_output[32];

    public:

        CCryptonightHeavyAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int algo, const uint64_t height)
            : Nan::AsyncWorker(callback), m_input(input), m_input_len(input_len), m_height(height), m_fn(get_cn_heavy_fn(algo)) {}

        void Execute () {
            m_fn(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &ctx, m_height);
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_heavy_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int algo = 0;
    uint64_t height = 0;

    int callback_arg_num = 1;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    }
    if (info.Length() >= 4) {
        if (!info[2]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 3 should be a number");
        algo = Nan::To<unsigned int>(info[2]).FromMaybe(0);
        callback_arg_num = 3;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightHeavyAsync(callback, Buffer::Data(target), Buffer::Length(target), algo, height));
}


class CCryptonightPicoAsync : public Nan::AsyncWorker {

    private:

        const char* const m_input;
        const uint32_t m_input_len;
        xmrig::cn_hash_fun m_fn;
        char m_output[32];

    public:

        CCryptonightPicoAsync(Nan::Callback* const callback, const char* const input, const uint32_t input_len, const int algo)
            : Nan::AsyncWorker(callback), m_input(input), m_input_len(input_len), m_fn(get_cn_pico_fn(algo)) {}

        void Execute () {
            m_fn(reinterpret_cast<const uint8_t*>(m_input), m_input_len, reinterpret_cast<uint8_t*>(m_output), &ctx, 0);
        }

        void HandleOKCallback () {
            Nan::HandleScope scope;

            v8::Local<v8::Value> argv[] = {
                Nan::Null(),
                v8::Local<v8::Value>(Nan::CopyBuffer(m_output, 32).ToLocalChecked())
            };
            callback->Call(2, argv, async_resource);
        }
};

NAN_METHOD(cryptonight_pico_async) {
    if (info.Length() < 2) return THROW_ERROR_EXCEPTION("You must provide at least two arguments.");

    Local<Object> target = info[0]->ToObject();
    if (!Buffer::HasInstance(target)) return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    int algo = 0;

    int callback_arg_num;
    if (info.Length() >= 3) {
        if (!info[1]->IsNumber()) return THROW_ERROR_EXCEPTION("Argument 2 should be a number");
        algo = Nan::To<int>(info[1]).FromMaybe(0);
        callback_arg_num = 2;
    } else {
        callback_arg_num = 1;
    }

    Callback *callback = new Nan::Callback(info[callback_arg_num].As<v8::Function>());
    Nan::AsyncQueueWorker(new CCryptonightPicoAsync(callback, Buffer::Data(target), Buffer::Length(target), algo));
}

*/

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_light").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_heavy").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_heavy)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight_pico").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_pico)).ToLocalChecked());
    Nan::Set(target, Nan::New("randomx").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(randomx)).ToLocalChecked());
    Nan::Set(target, Nan::New("argon2").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(argon2)).ToLocalChecked());
    Nan::Set(target, Nan::New("k12").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(k12)).ToLocalChecked());
    Nan::Set(target, Nan::New("getCompact").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(getCompact)).ToLocalChecked());
    
    //Nan::Set(target, Nan::New("cryptonight_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_async)).ToLocalChecked());
    //Nan::Set(target, Nan::New("cryptonight_light_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light_async)).ToLocalChecked());
    //Nan::Set(target, Nan::New("cryptonight_heavy_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_heavy_async)).ToLocalChecked());
    //Nan::Set(target, Nan::New("cryptonight_pico_async").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_pico_async)).ToLocalChecked());
}

NODE_MODULE(cryptonight, init)