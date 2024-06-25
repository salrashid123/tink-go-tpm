// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v4.25.1
// source: proto/tinktpm.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type HashType int32

const (
	HashType_UNKNOWN_HASH HashType = 0
	HashType_SHA1         HashType = 1 // Using SHA1 for digital signature is deprecated but HMAC-SHA1 is
	// fine.
	HashType_SHA384 HashType = 2
	HashType_SHA256 HashType = 3
	HashType_SHA512 HashType = 4
	HashType_SHA224 HashType = 5
)

// Enum value maps for HashType.
var (
	HashType_name = map[int32]string{
		0: "UNKNOWN_HASH",
		1: "SHA1",
		2: "SHA384",
		3: "SHA256",
		4: "SHA512",
		5: "SHA224",
	}
	HashType_value = map[string]int32{
		"UNKNOWN_HASH": 0,
		"SHA1":         1,
		"SHA384":       2,
		"SHA256":       3,
		"SHA512":       4,
		"SHA224":       5,
	}
)

func (x HashType) Enum() *HashType {
	p := new(HashType)
	*p = x
	return p
}

func (x HashType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (HashType) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_tinktpm_proto_enumTypes[0].Descriptor()
}

func (HashType) Type() protoreflect.EnumType {
	return &file_proto_tinktpm_proto_enumTypes[0]
}

func (x HashType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use HashType.Descriptor instead.
func (HashType) EnumDescriptor() ([]byte, []int) {
	return file_proto_tinktpm_proto_rawDescGZIP(), []int{0}
}

type TPMKey_KeyType int32

const (
	TPMKey_SYMMETRIC TPMKey_KeyType = 0
	TPMKey_HMAC      TPMKey_KeyType = 1
)

// Enum value maps for TPMKey_KeyType.
var (
	TPMKey_KeyType_name = map[int32]string{
		0: "SYMMETRIC",
		1: "HMAC",
	}
	TPMKey_KeyType_value = map[string]int32{
		"SYMMETRIC": 0,
		"HMAC":      1,
	}
)

func (x TPMKey_KeyType) Enum() *TPMKey_KeyType {
	p := new(TPMKey_KeyType)
	*p = x
	return p
}

func (x TPMKey_KeyType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (TPMKey_KeyType) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_tinktpm_proto_enumTypes[1].Descriptor()
}

func (TPMKey_KeyType) Type() protoreflect.EnumType {
	return &file_proto_tinktpm_proto_enumTypes[1]
}

func (x TPMKey_KeyType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use TPMKey_KeyType.Descriptor instead.
func (TPMKey_KeyType) EnumDescriptor() ([]byte, []int) {
	return file_proto_tinktpm_proto_rawDescGZIP(), []int{0, 0}
}

type TPMKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version uint32         `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
	KeyType TPMKey_KeyType `protobuf:"varint,2,opt,name=keyType,proto3,enum=proto.TPMKey_KeyType" json:"keyType,omitempty"`
	// Types that are assignable to Key:
	//
	//	*TPMKey_HmacKey
	Key isTPMKey_Key `protobuf_oneof:"Key"`
}

func (x *TPMKey) Reset() {
	*x = TPMKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_tinktpm_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TPMKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TPMKey) ProtoMessage() {}

func (x *TPMKey) ProtoReflect() protoreflect.Message {
	mi := &file_proto_tinktpm_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TPMKey.ProtoReflect.Descriptor instead.
func (*TPMKey) Descriptor() ([]byte, []int) {
	return file_proto_tinktpm_proto_rawDescGZIP(), []int{0}
}

func (x *TPMKey) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

func (x *TPMKey) GetKeyType() TPMKey_KeyType {
	if x != nil {
		return x.KeyType
	}
	return TPMKey_SYMMETRIC
}

func (m *TPMKey) GetKey() isTPMKey_Key {
	if m != nil {
		return m.Key
	}
	return nil
}

func (x *TPMKey) GetHmacKey() *HMACKey {
	if x, ok := x.GetKey().(*TPMKey_HmacKey); ok {
		return x.HmacKey
	}
	return nil
}

type isTPMKey_Key interface {
	isTPMKey_Key()
}

type TPMKey_HmacKey struct {
	HmacKey *HMACKey `protobuf:"bytes,3,opt,name=hmacKey,proto3,oneof"`
}

func (*TPMKey_HmacKey) isTPMKey_Key() {}

// key_type: type.googleapis.com/google.crypto.tink.TPMHmacKey
type HMACKey struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name         []byte         `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Public       []byte         `protobuf:"bytes,2,opt,name=public,proto3" json:"public,omitempty"`
	Private      []byte         `protobuf:"bytes,3,opt,name=private,proto3" json:"private,omitempty"`
	PolicyDigest []byte         `protobuf:"bytes,4,opt,name=policy_digest,json=policyDigest,proto3" json:"policy_digest,omitempty"`
	KeyFormat    *HMACKeyFormat `protobuf:"bytes,5,opt,name=key_format,json=keyFormat,proto3" json:"key_format,omitempty"`
}

func (x *HMACKey) Reset() {
	*x = HMACKey{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_tinktpm_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HMACKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HMACKey) ProtoMessage() {}

func (x *HMACKey) ProtoReflect() protoreflect.Message {
	mi := &file_proto_tinktpm_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HMACKey.ProtoReflect.Descriptor instead.
func (*HMACKey) Descriptor() ([]byte, []int) {
	return file_proto_tinktpm_proto_rawDescGZIP(), []int{1}
}

func (x *HMACKey) GetName() []byte {
	if x != nil {
		return x.Name
	}
	return nil
}

func (x *HMACKey) GetPublic() []byte {
	if x != nil {
		return x.Public
	}
	return nil
}

func (x *HMACKey) GetPrivate() []byte {
	if x != nil {
		return x.Private
	}
	return nil
}

func (x *HMACKey) GetPolicyDigest() []byte {
	if x != nil {
		return x.PolicyDigest
	}
	return nil
}

func (x *HMACKey) GetKeyFormat() *HMACKeyFormat {
	if x != nil {
		return x.KeyFormat
	}
	return nil
}

type HMACParams struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hash    HashType `protobuf:"varint,1,opt,name=hash,proto3,enum=proto.HashType" json:"hash,omitempty"` // HashType is an enum.
	TagSize uint32   `protobuf:"varint,2,opt,name=tag_size,json=tagSize,proto3" json:"tag_size,omitempty"`
}

func (x *HMACParams) Reset() {
	*x = HMACParams{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_tinktpm_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HMACParams) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HMACParams) ProtoMessage() {}

func (x *HMACParams) ProtoReflect() protoreflect.Message {
	mi := &file_proto_tinktpm_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HMACParams.ProtoReflect.Descriptor instead.
func (*HMACParams) Descriptor() ([]byte, []int) {
	return file_proto_tinktpm_proto_rawDescGZIP(), []int{2}
}

func (x *HMACParams) GetHash() HashType {
	if x != nil {
		return x.Hash
	}
	return HashType_UNKNOWN_HASH
}

func (x *HMACParams) GetTagSize() uint32 {
	if x != nil {
		return x.TagSize
	}
	return 0
}

type HMACKeyFormat struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Params  *HMACParams `protobuf:"bytes,1,opt,name=params,proto3" json:"params,omitempty"`
	KeySize uint32      `protobuf:"varint,2,opt,name=key_size,json=keySize,proto3" json:"key_size,omitempty"`
	Version uint32      `protobuf:"varint,3,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *HMACKeyFormat) Reset() {
	*x = HMACKeyFormat{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_tinktpm_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HMACKeyFormat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HMACKeyFormat) ProtoMessage() {}

func (x *HMACKeyFormat) ProtoReflect() protoreflect.Message {
	mi := &file_proto_tinktpm_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HMACKeyFormat.ProtoReflect.Descriptor instead.
func (*HMACKeyFormat) Descriptor() ([]byte, []int) {
	return file_proto_tinktpm_proto_rawDescGZIP(), []int{3}
}

func (x *HMACKeyFormat) GetParams() *HMACParams {
	if x != nil {
		return x.Params
	}
	return nil
}

func (x *HMACKeyFormat) GetKeySize() uint32 {
	if x != nil {
		return x.KeySize
	}
	return 0
}

func (x *HMACKeyFormat) GetVersion() uint32 {
	if x != nil {
		return x.Version
	}
	return 0
}

var File_proto_tinktpm_proto protoreflect.FileDescriptor

var file_proto_tinktpm_proto_rawDesc = []byte{
	0x0a, 0x13, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74, 0x69, 0x6e, 0x6b, 0x74, 0x70, 0x6d, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xaa, 0x01, 0x0a,
	0x06, 0x54, 0x50, 0x4d, 0x4b, 0x65, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x12, 0x2f, 0x0a, 0x07, 0x6b, 0x65, 0x79, 0x54, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x15, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x54, 0x50, 0x4d, 0x4b, 0x65,
	0x79, 0x2e, 0x4b, 0x65, 0x79, 0x54, 0x79, 0x70, 0x65, 0x52, 0x07, 0x6b, 0x65, 0x79, 0x54, 0x79,
	0x70, 0x65, 0x12, 0x2a, 0x0a, 0x07, 0x68, 0x6d, 0x61, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x48, 0x4d, 0x41, 0x43,
	0x4b, 0x65, 0x79, 0x48, 0x00, 0x52, 0x07, 0x68, 0x6d, 0x61, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x22,
	0x0a, 0x07, 0x4b, 0x65, 0x79, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0d, 0x0a, 0x09, 0x53, 0x59, 0x4d,
	0x4d, 0x45, 0x54, 0x52, 0x49, 0x43, 0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x48, 0x4d, 0x41, 0x43,
	0x10, 0x01, 0x42, 0x05, 0x0a, 0x03, 0x4b, 0x65, 0x79, 0x22, 0xa9, 0x01, 0x0a, 0x07, 0x48, 0x4d,
	0x41, 0x43, 0x4b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x12, 0x23, 0x0a, 0x0d, 0x70,
	0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0c, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74,
	0x12, 0x33, 0x0a, 0x0a, 0x6b, 0x65, 0x79, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x48, 0x4d, 0x41,
	0x43, 0x4b, 0x65, 0x79, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x52, 0x09, 0x6b, 0x65, 0x79, 0x46,
	0x6f, 0x72, 0x6d, 0x61, 0x74, 0x22, 0x4c, 0x0a, 0x0a, 0x48, 0x4d, 0x41, 0x43, 0x50, 0x61, 0x72,
	0x61, 0x6d, 0x73, 0x12, 0x23, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x0f, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x48, 0x61, 0x73, 0x68, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x12, 0x19, 0x0a, 0x08, 0x74, 0x61, 0x67, 0x5f,
	0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x74, 0x61, 0x67, 0x53,
	0x69, 0x7a, 0x65, 0x22, 0x6f, 0x0a, 0x0d, 0x48, 0x4d, 0x41, 0x43, 0x4b, 0x65, 0x79, 0x46, 0x6f,
	0x72, 0x6d, 0x61, 0x74, 0x12, 0x29, 0x0a, 0x06, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x11, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x48, 0x4d, 0x41,
	0x43, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x52, 0x06, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12,
	0x19, 0x0a, 0x08, 0x6b, 0x65, 0x79, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x07, 0x6b, 0x65, 0x79, 0x53, 0x69, 0x7a, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x2a, 0x56, 0x0a, 0x08, 0x48, 0x61, 0x73, 0x68, 0x54, 0x79, 0x70, 0x65,
	0x12, 0x10, 0x0a, 0x0c, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x5f, 0x48, 0x41, 0x53, 0x48,
	0x10, 0x00, 0x12, 0x08, 0x0a, 0x04, 0x53, 0x48, 0x41, 0x31, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06,
	0x53, 0x48, 0x41, 0x33, 0x38, 0x34, 0x10, 0x02, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x48, 0x41, 0x32,
	0x35, 0x36, 0x10, 0x03, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x48, 0x41, 0x35, 0x31, 0x32, 0x10, 0x04,
	0x12, 0x0a, 0x0a, 0x06, 0x53, 0x48, 0x41, 0x32, 0x32, 0x34, 0x10, 0x05, 0x42, 0x2e, 0x5a, 0x2c,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x61, 0x6c, 0x72, 0x61,
	0x73, 0x68, 0x69, 0x64, 0x31, 0x32, 0x33, 0x2f, 0x74, 0x69, 0x6e, 0x6b, 0x2d, 0x67, 0x6f, 0x2d,
	0x74, 0x70, 0x6d, 0x2f, 0x76, 0x32, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_tinktpm_proto_rawDescOnce sync.Once
	file_proto_tinktpm_proto_rawDescData = file_proto_tinktpm_proto_rawDesc
)

func file_proto_tinktpm_proto_rawDescGZIP() []byte {
	file_proto_tinktpm_proto_rawDescOnce.Do(func() {
		file_proto_tinktpm_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_tinktpm_proto_rawDescData)
	})
	return file_proto_tinktpm_proto_rawDescData
}

var file_proto_tinktpm_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_proto_tinktpm_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_proto_tinktpm_proto_goTypes = []interface{}{
	(HashType)(0),         // 0: proto.HashType
	(TPMKey_KeyType)(0),   // 1: proto.TPMKey.KeyType
	(*TPMKey)(nil),        // 2: proto.TPMKey
	(*HMACKey)(nil),       // 3: proto.HMACKey
	(*HMACParams)(nil),    // 4: proto.HMACParams
	(*HMACKeyFormat)(nil), // 5: proto.HMACKeyFormat
}
var file_proto_tinktpm_proto_depIdxs = []int32{
	1, // 0: proto.TPMKey.keyType:type_name -> proto.TPMKey.KeyType
	3, // 1: proto.TPMKey.hmacKey:type_name -> proto.HMACKey
	5, // 2: proto.HMACKey.key_format:type_name -> proto.HMACKeyFormat
	0, // 3: proto.HMACParams.hash:type_name -> proto.HashType
	4, // 4: proto.HMACKeyFormat.params:type_name -> proto.HMACParams
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_proto_tinktpm_proto_init() }
func file_proto_tinktpm_proto_init() {
	if File_proto_tinktpm_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_tinktpm_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TPMKey); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_tinktpm_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HMACKey); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_tinktpm_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HMACParams); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_tinktpm_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HMACKeyFormat); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_proto_tinktpm_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*TPMKey_HmacKey)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_tinktpm_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_tinktpm_proto_goTypes,
		DependencyIndexes: file_proto_tinktpm_proto_depIdxs,
		EnumInfos:         file_proto_tinktpm_proto_enumTypes,
		MessageInfos:      file_proto_tinktpm_proto_msgTypes,
	}.Build()
	File_proto_tinktpm_proto = out.File
	file_proto_tinktpm_proto_rawDesc = nil
	file_proto_tinktpm_proto_goTypes = nil
	file_proto_tinktpm_proto_depIdxs = nil
}