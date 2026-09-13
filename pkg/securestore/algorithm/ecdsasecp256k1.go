package algorithm

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// secp256k1 OID: 1.3.132.0.10
var oidSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

// OID: 1.2.840.10045.2.1 (ecPublicKey / id-ecPublicKey)
var oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// secp256k1 算法标识符
const ESecp256k1 = "ecdsa-secp256k1"

// secpPrivKey 带缓存的 secp256k1 私钥包装器
type secpPrivKey struct {
	priv     *btcec.PrivateKey
	pubBytes []byte // 65字节未压缩公钥: 0x04 || X(32) || Y(32)
}

func (k *secpPrivKey) PubKey() *btcec.PublicKey { return k.priv.PubKey() }
func (k *secpPrivKey) Serialize() []byte        { return k.priv.Serialize() }
func (k *secpPrivKey) Zero()                    { k.priv.Zero() }

// Secp256k1Algorithm secp256k1 椭圆曲线 ECDSA 算法实现
type Secp256k1Algorithm struct{ algorithmID string }

func NewSecp256k1Algorithm() *Secp256k1Algorithm {
	return &Secp256k1Algorithm{algorithmID: ESecp256k1}
}

func (a *Secp256k1Algorithm) AlgorithmID() string { return a.algorithmID }

func (a *Secp256k1Algorithm) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate secp256k1 key: %w", err)
	}
	wrapped := wrapPrivKey(priv)
	return wrapped, wrapped.PubKey(), nil
}

func (a *Secp256k1Algorithm) NewPrivateKeyFromBytes(privKeyBytes []byte) (crypto.PrivateKey, error) {
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32, got %d", len(privKeyBytes))
	}
	priv, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	// 验证 D 值: D > 0 且 D < N
	d := priv.ToECDSA().D
	if d.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key: D is zero or negative")
	}
	N := btcec.S256().Params().N
	if d.Cmp(N) >= 0 {
		return nil, fmt.Errorf("invalid private key: D >= N (curve order)")
	}
	return wrapPrivKey(priv), nil
}

// Sign 对消息签名，返回 65 字节的原始签名: R(32字节) || S(32字节) || V(1字节)
//
// 签名格式:
//   - R: 32字节，secp256k1 曲线点 R 的 x 坐标，big-endian
//   - S: 32字节，签名标量，big-endian
//   - V: 1字节，R 点 y 坐标的奇偶性标识
//   - 0: R.y 坐标为偶数
//   - 1: R.y 坐标为奇数
//     (V 值与链无关，Bitcoin 需 +27，Ethereum 需根据 chainId 另行计算)
//
// 该格式为 Bitcoin/Bitcoin Cash 使用的 "compact" 签名格式（去掉前缀 0x1b/0x1c/0x1d/0x1e 标记，
// 改为直接追加 V 字节），不同于 Ethereum 的 V = 27/28 + chainId*2，
// 也不同于 DER 编码。调用方可根据链需求自行转换。
func (a *Secp256k1Algorithm) Sign(privateKey crypto.PrivateKey, message []byte) ([]byte, error) {
	k, ok := privateKey.(*secpPrivKey)
	if !ok {
		return nil, fmt.Errorf("privateKey is not *secpPrivKey")
	}
	// btcecdsa.SignCompact 返回 65 字节: (27+v) || R(32) || S(32)
	// v = (overflow_bit << 1) + oddness_bit，范围 [0, 3]
	compact := btcecdsa.SignCompact(k.priv, message, false)
	rBytes := compact[1:33]
	sBytes := compact[33:65]

	// V: 直接从 SignCompact 的 recovery_code 提取 oddness
	// recovery_code = 27 + (overflow << 1) + oddness
	// oddness = recovery_code & 1 (bit 0)
	// 注意: 不要用 DecompressY 重新计算，因为 low-S 规范化时会翻转 oddness
	v := (compact[0] - 27) & 1 // 提取 bit 0 (oddness)

	result := make([]byte, 65)
	copy(result[0:32], rBytes)  // R
	copy(result[32:64], sBytes) // S
	result[64] = v              // V
	return result, nil
}

func (a *Secp256k1Algorithm) SerializePrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	k, ok := privateKey.(*secpPrivKey)
	if !ok {
		return nil, fmt.Errorf("expected *secpPrivKey, got %T", privateKey)
	}
	return marshalPKCS8Secp256k1(k.priv.Serialize(), k.pubBytes)
}

func (a *Secp256k1Algorithm) SerializePublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	pub, ok := publicKey.(*btcec.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected *btcec.PublicKey, got %T", publicKey)
	}
	uncompressed := pub.SerializeUncompressed()
	return marshalPKIXSecp256k1(uncompressed)
}

func (a *Secp256k1Algorithm) ParsePrivateKey(derBytes []byte) (crypto.PrivateKey, error) {
	privBytes, err := parsePKCS8Secp256k1(derBytes)
	if err != nil {
		return nil, err
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	return wrapPrivKey(priv), nil
}

func (a *Secp256k1Algorithm) ClearPrivateKey(privateKey crypto.PrivateKey) {
	if k, ok := privateKey.(*secpPrivKey); ok {
		k.Zero()
	}
}

func (a *Secp256k1Algorithm) HashFunc() crypto.Hash { return crypto.SHA256 }

func init() {
	if err := Register(NewSecp256k1Algorithm()); err != nil {
		panic(fmt.Sprintf("warning: failed to register secp256k1 curve: %v", err))
	}
}

// wrapPrivKey 将 btcec.PrivateKey 包装为 secpPrivKey，并预计算未压缩公钥
func wrapPrivKey(priv *btcec.PrivateKey) *secpPrivKey {
	return &secpPrivKey{priv: priv, pubBytes: computeUncompressedPub(priv)}
}

// computeUncompressedPub 计算私钥对应的未压缩公钥字节 (0x04 || X || Y)
func computeUncompressedPub(priv *btcec.PrivateKey) []byte {
	curve := btcec.S256()
	d := priv.Serialize()
	Gx, Gy := curve.ScalarBaseMult(d)
	xBytes := bigIntToBytes(Gx, 32)
	yBytes := bigIntToBytes(Gy, 32)
	result := make([]byte, 65)
	result[0] = 0x04
	copy(result[1:33], xBytes)
	copy(result[33:65], yBytes)
	return result
}

// bigIntToBytes 将 *big.Int 转为固定长度的 big-endian 字节切片
func bigIntToBytes(v *big.Int, length int) []byte {
	b := v.Bytes()
	if len(b) > length {
		b = b[len(b)-length:]
	}
	if len(b) < length {
		padded := make([]byte, length)
		copy(padded[length-len(b):], b)
		return padded
	}
	return b
}

// --- PKCS8 / PKIX DER 序列化 ---

// marshalPKCS8Secp256k1 将私钥序列化为 PKCS8 DER
func marshalPKCS8Secp256k1(d, uncompressedPub []byte) ([]byte, error) {
	// uncompressedPub[0]=0x04, [1:33]=X, [33:65]=Y
	x := uncompressedPub[1:33]
	y := uncompressedPub[33:65]

	// ECPrivateKey (RFC 5915)
	ecPrivDER, err := asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: d,
		PublicKey: asn1.BitString{
			Bytes:     append([]byte{0x04}, append(x, y...)...),
			BitLength: 65 * 8,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal ECPrivateKey: %w", err)
	}

	// PKCS8
	pkcs8 := pkcs8PrivateKey{
		Version: 0,
		Algo: pkixAlgorithmIdentifier{
			Algorithm: oidECPublicKey,
			Parameters: asn1.RawValue{
				FullBytes: asn1MarshalOID(oidSecp256k1),
			},
		},
		PrivateKey: ecPrivDER,
	}
	return asn1.Marshal(pkcs8)
}

// marshalPKIXSecp256k1 将公钥序列化为 PKIX SubjectPublicKeyInfo DER
func marshalPKIXSecp256k1(uncompressedPub []byte) ([]byte, error) {
	algoBytes, err := asn1.Marshal(pkixAlgorithmIdentifier{
		Algorithm: oidECPublicKey,
		Parameters: asn1.RawValue{
			FullBytes: asn1MarshalOID(oidSecp256k1),
		},
	})
	if err != nil {
		return nil, err
	}
	spki := subjectPublicKeyInfo{
		Algorithm: asn1.RawValue{FullBytes: algoBytes},
		PublicKey: asn1.BitString{
			Bytes:     uncompressedPub,
			BitLength: len(uncompressedPub) * 8,
		},
	}
	return asn1.Marshal(spki)
}

// parsePKCS8Secp256k1 解析 PKCS8 DER，返回私钥字节
func parsePKCS8Secp256k1(der []byte) ([]byte, error) {
	var pkcs8 pkcs8PrivateKey
	if _, err := asn1.Unmarshal(der, &pkcs8); err != nil {
		return nil, fmt.Errorf("unmarshal PKCS8: %w", err)
	}
	if !pkcs8.Algo.Algorithm.Equal(oidECPublicKey) {
		return nil, fmt.Errorf("unsupported algorithm: %v", pkcs8.Algo.Algorithm)
	}
	var ecPriv ecPrivateKey
	if _, err := asn1.Unmarshal(pkcs8.PrivateKey, &ecPriv); err != nil {
		return nil, fmt.Errorf("unmarshal ECPrivateKey: %w", err)
	}
	if len(ecPriv.PrivateKey) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(ecPriv.PrivateKey))
	}
	return ecPriv.PrivateKey, nil
}

// asn1MarshalOID 将 asn1.ObjectIdentifier 编码为 DER 字节 (tag=0x06)
func asn1MarshalOID(oid asn1.ObjectIdentifier) []byte {
	bytes, _ := asn1.Marshal(oid) // 总是成功
	return bytes
}

// --- ASN.1 DER 结构体 ---

type pkcs8PrivateKey struct {
	Version    int
	Algo       pkixAlgorithmIdentifier
	PrivateKey []byte `asn1:"explicit.tag:0"`
}

type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type ecPrivateKey struct {
	Version    int
	PrivateKey []byte
	Parameters asn1.RawValue  `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
}

type subjectPublicKeyInfo struct {
	Algorithm asn1.RawValue
	PublicKey asn1.BitString
}
