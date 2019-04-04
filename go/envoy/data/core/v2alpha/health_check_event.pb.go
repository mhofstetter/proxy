// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/data/core/v2alpha/health_check_event.proto

package envoy_data_core_v2alpha

import (
	fmt "fmt"
	core "github.com/cilium/proxy/go/envoy/api/v2/core"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/golang/protobuf/proto"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	_ "github.com/lyft/protoc-gen-validate/validate"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type HealthCheckFailureType int32

const (
	HealthCheckFailureType_ACTIVE  HealthCheckFailureType = 0
	HealthCheckFailureType_PASSIVE HealthCheckFailureType = 1
	HealthCheckFailureType_NETWORK HealthCheckFailureType = 2
)

var HealthCheckFailureType_name = map[int32]string{
	0: "ACTIVE",
	1: "PASSIVE",
	2: "NETWORK",
}

var HealthCheckFailureType_value = map[string]int32{
	"ACTIVE":  0,
	"PASSIVE": 1,
	"NETWORK": 2,
}

func (x HealthCheckFailureType) String() string {
	return proto.EnumName(HealthCheckFailureType_name, int32(x))
}

func (HealthCheckFailureType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_e866c90440508830, []int{0}
}

type HealthCheckerType int32

const (
	HealthCheckerType_HTTP  HealthCheckerType = 0
	HealthCheckerType_TCP   HealthCheckerType = 1
	HealthCheckerType_GRPC  HealthCheckerType = 2
	HealthCheckerType_REDIS HealthCheckerType = 3
)

var HealthCheckerType_name = map[int32]string{
	0: "HTTP",
	1: "TCP",
	2: "GRPC",
	3: "REDIS",
}

var HealthCheckerType_value = map[string]int32{
	"HTTP":  0,
	"TCP":   1,
	"GRPC":  2,
	"REDIS": 3,
}

func (x HealthCheckerType) String() string {
	return proto.EnumName(HealthCheckerType_name, int32(x))
}

func (HealthCheckerType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_e866c90440508830, []int{1}
}

type HealthCheckEvent struct {
	HealthCheckerType HealthCheckerType `protobuf:"varint,1,opt,name=health_checker_type,json=healthCheckerType,proto3,enum=envoy.data.core.v2alpha.HealthCheckerType" json:"health_checker_type,omitempty"`
	Host              *core.Address     `protobuf:"bytes,2,opt,name=host,proto3" json:"host,omitempty"`
	ClusterName       string            `protobuf:"bytes,3,opt,name=cluster_name,json=clusterName,proto3" json:"cluster_name,omitempty"`
	// Types that are valid to be assigned to Event:
	//	*HealthCheckEvent_EjectUnhealthyEvent
	//	*HealthCheckEvent_AddHealthyEvent
	//	*HealthCheckEvent_HealthCheckFailureEvent
	//	*HealthCheckEvent_DegradedHealthyHost
	//	*HealthCheckEvent_NoLongerDegradedHost
	Event isHealthCheckEvent_Event `protobuf_oneof:"event"`
	// Timestamp for event.
	Timestamp            *timestamp.Timestamp `protobuf:"bytes,6,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *HealthCheckEvent) Reset()         { *m = HealthCheckEvent{} }
func (m *HealthCheckEvent) String() string { return proto.CompactTextString(m) }
func (*HealthCheckEvent) ProtoMessage()    {}
func (*HealthCheckEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_e866c90440508830, []int{0}
}

func (m *HealthCheckEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HealthCheckEvent.Unmarshal(m, b)
}
func (m *HealthCheckEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HealthCheckEvent.Marshal(b, m, deterministic)
}
func (m *HealthCheckEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HealthCheckEvent.Merge(m, src)
}
func (m *HealthCheckEvent) XXX_Size() int {
	return xxx_messageInfo_HealthCheckEvent.Size(m)
}
func (m *HealthCheckEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_HealthCheckEvent.DiscardUnknown(m)
}

var xxx_messageInfo_HealthCheckEvent proto.InternalMessageInfo

func (m *HealthCheckEvent) GetHealthCheckerType() HealthCheckerType {
	if m != nil {
		return m.HealthCheckerType
	}
	return HealthCheckerType_HTTP
}

func (m *HealthCheckEvent) GetHost() *core.Address {
	if m != nil {
		return m.Host
	}
	return nil
}

func (m *HealthCheckEvent) GetClusterName() string {
	if m != nil {
		return m.ClusterName
	}
	return ""
}

type isHealthCheckEvent_Event interface {
	isHealthCheckEvent_Event()
}

type HealthCheckEvent_EjectUnhealthyEvent struct {
	EjectUnhealthyEvent *HealthCheckEjectUnhealthy `protobuf:"bytes,4,opt,name=eject_unhealthy_event,json=ejectUnhealthyEvent,proto3,oneof"`
}

type HealthCheckEvent_AddHealthyEvent struct {
	AddHealthyEvent *HealthCheckAddHealthy `protobuf:"bytes,5,opt,name=add_healthy_event,json=addHealthyEvent,proto3,oneof"`
}

type HealthCheckEvent_HealthCheckFailureEvent struct {
	HealthCheckFailureEvent *HealthCheckFailure `protobuf:"bytes,7,opt,name=health_check_failure_event,json=healthCheckFailureEvent,proto3,oneof"`
}

type HealthCheckEvent_DegradedHealthyHost struct {
	DegradedHealthyHost *DegradedHealthyHost `protobuf:"bytes,8,opt,name=degraded_healthy_host,json=degradedHealthyHost,proto3,oneof"`
}

type HealthCheckEvent_NoLongerDegradedHost struct {
	NoLongerDegradedHost *NoLongerDegradedHost `protobuf:"bytes,9,opt,name=no_longer_degraded_host,json=noLongerDegradedHost,proto3,oneof"`
}

func (*HealthCheckEvent_EjectUnhealthyEvent) isHealthCheckEvent_Event() {}

func (*HealthCheckEvent_AddHealthyEvent) isHealthCheckEvent_Event() {}

func (*HealthCheckEvent_HealthCheckFailureEvent) isHealthCheckEvent_Event() {}

func (*HealthCheckEvent_DegradedHealthyHost) isHealthCheckEvent_Event() {}

func (*HealthCheckEvent_NoLongerDegradedHost) isHealthCheckEvent_Event() {}

func (m *HealthCheckEvent) GetEvent() isHealthCheckEvent_Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func (m *HealthCheckEvent) GetEjectUnhealthyEvent() *HealthCheckEjectUnhealthy {
	if x, ok := m.GetEvent().(*HealthCheckEvent_EjectUnhealthyEvent); ok {
		return x.EjectUnhealthyEvent
	}
	return nil
}

func (m *HealthCheckEvent) GetAddHealthyEvent() *HealthCheckAddHealthy {
	if x, ok := m.GetEvent().(*HealthCheckEvent_AddHealthyEvent); ok {
		return x.AddHealthyEvent
	}
	return nil
}

func (m *HealthCheckEvent) GetHealthCheckFailureEvent() *HealthCheckFailure {
	if x, ok := m.GetEvent().(*HealthCheckEvent_HealthCheckFailureEvent); ok {
		return x.HealthCheckFailureEvent
	}
	return nil
}

func (m *HealthCheckEvent) GetDegradedHealthyHost() *DegradedHealthyHost {
	if x, ok := m.GetEvent().(*HealthCheckEvent_DegradedHealthyHost); ok {
		return x.DegradedHealthyHost
	}
	return nil
}

func (m *HealthCheckEvent) GetNoLongerDegradedHost() *NoLongerDegradedHost {
	if x, ok := m.GetEvent().(*HealthCheckEvent_NoLongerDegradedHost); ok {
		return x.NoLongerDegradedHost
	}
	return nil
}

func (m *HealthCheckEvent) GetTimestamp() *timestamp.Timestamp {
	if m != nil {
		return m.Timestamp
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*HealthCheckEvent) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*HealthCheckEvent_EjectUnhealthyEvent)(nil),
		(*HealthCheckEvent_AddHealthyEvent)(nil),
		(*HealthCheckEvent_HealthCheckFailureEvent)(nil),
		(*HealthCheckEvent_DegradedHealthyHost)(nil),
		(*HealthCheckEvent_NoLongerDegradedHost)(nil),
	}
}

type HealthCheckEjectUnhealthy struct {
	// The type of failure that caused this ejection.
	FailureType          HealthCheckFailureType `protobuf:"varint,1,opt,name=failure_type,json=failureType,proto3,enum=envoy.data.core.v2alpha.HealthCheckFailureType" json:"failure_type,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *HealthCheckEjectUnhealthy) Reset()         { *m = HealthCheckEjectUnhealthy{} }
func (m *HealthCheckEjectUnhealthy) String() string { return proto.CompactTextString(m) }
func (*HealthCheckEjectUnhealthy) ProtoMessage()    {}
func (*HealthCheckEjectUnhealthy) Descriptor() ([]byte, []int) {
	return fileDescriptor_e866c90440508830, []int{1}
}

func (m *HealthCheckEjectUnhealthy) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HealthCheckEjectUnhealthy.Unmarshal(m, b)
}
func (m *HealthCheckEjectUnhealthy) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HealthCheckEjectUnhealthy.Marshal(b, m, deterministic)
}
func (m *HealthCheckEjectUnhealthy) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HealthCheckEjectUnhealthy.Merge(m, src)
}
func (m *HealthCheckEjectUnhealthy) XXX_Size() int {
	return xxx_messageInfo_HealthCheckEjectUnhealthy.Size(m)
}
func (m *HealthCheckEjectUnhealthy) XXX_DiscardUnknown() {
	xxx_messageInfo_HealthCheckEjectUnhealthy.DiscardUnknown(m)
}

var xxx_messageInfo_HealthCheckEjectUnhealthy proto.InternalMessageInfo

func (m *HealthCheckEjectUnhealthy) GetFailureType() HealthCheckFailureType {
	if m != nil {
		return m.FailureType
	}
	return HealthCheckFailureType_ACTIVE
}

type HealthCheckAddHealthy struct {
	// Whether this addition is the result of the first ever health check on a host, in which case
	// the configured :ref:`healthy threshold <envoy_api_field_core.HealthCheck.healthy_threshold>`
	// is bypassed and the host is immediately added.
	FirstCheck           bool     `protobuf:"varint,1,opt,name=first_check,json=firstCheck,proto3" json:"first_check,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HealthCheckAddHealthy) Reset()         { *m = HealthCheckAddHealthy{} }
func (m *HealthCheckAddHealthy) String() string { return proto.CompactTextString(m) }
func (*HealthCheckAddHealthy) ProtoMessage()    {}
func (*HealthCheckAddHealthy) Descriptor() ([]byte, []int) {
	return fileDescriptor_e866c90440508830, []int{2}
}

func (m *HealthCheckAddHealthy) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HealthCheckAddHealthy.Unmarshal(m, b)
}
func (m *HealthCheckAddHealthy) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HealthCheckAddHealthy.Marshal(b, m, deterministic)
}
func (m *HealthCheckAddHealthy) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HealthCheckAddHealthy.Merge(m, src)
}
func (m *HealthCheckAddHealthy) XXX_Size() int {
	return xxx_messageInfo_HealthCheckAddHealthy.Size(m)
}
func (m *HealthCheckAddHealthy) XXX_DiscardUnknown() {
	xxx_messageInfo_HealthCheckAddHealthy.DiscardUnknown(m)
}

var xxx_messageInfo_HealthCheckAddHealthy proto.InternalMessageInfo

func (m *HealthCheckAddHealthy) GetFirstCheck() bool {
	if m != nil {
		return m.FirstCheck
	}
	return false
}

type HealthCheckFailure struct {
	// The type of failure that caused this event.
	FailureType HealthCheckFailureType `protobuf:"varint,1,opt,name=failure_type,json=failureType,proto3,enum=envoy.data.core.v2alpha.HealthCheckFailureType" json:"failure_type,omitempty"`
	// Whether this event is the result of the first ever health check on a host.
	FirstCheck           bool     `protobuf:"varint,2,opt,name=first_check,json=firstCheck,proto3" json:"first_check,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HealthCheckFailure) Reset()         { *m = HealthCheckFailure{} }
func (m *HealthCheckFailure) String() string { return proto.CompactTextString(m) }
func (*HealthCheckFailure) ProtoMessage()    {}
func (*HealthCheckFailure) Descriptor() ([]byte, []int) {
	return fileDescriptor_e866c90440508830, []int{3}
}

func (m *HealthCheckFailure) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HealthCheckFailure.Unmarshal(m, b)
}
func (m *HealthCheckFailure) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HealthCheckFailure.Marshal(b, m, deterministic)
}
func (m *HealthCheckFailure) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HealthCheckFailure.Merge(m, src)
}
func (m *HealthCheckFailure) XXX_Size() int {
	return xxx_messageInfo_HealthCheckFailure.Size(m)
}
func (m *HealthCheckFailure) XXX_DiscardUnknown() {
	xxx_messageInfo_HealthCheckFailure.DiscardUnknown(m)
}

var xxx_messageInfo_HealthCheckFailure proto.InternalMessageInfo

func (m *HealthCheckFailure) GetFailureType() HealthCheckFailureType {
	if m != nil {
		return m.FailureType
	}
	return HealthCheckFailureType_ACTIVE
}

func (m *HealthCheckFailure) GetFirstCheck() bool {
	if m != nil {
		return m.FirstCheck
	}
	return false
}

type DegradedHealthyHost struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DegradedHealthyHost) Reset()         { *m = DegradedHealthyHost{} }
func (m *DegradedHealthyHost) String() string { return proto.CompactTextString(m) }
func (*DegradedHealthyHost) ProtoMessage()    {}
func (*DegradedHealthyHost) Descriptor() ([]byte, []int) {
	return fileDescriptor_e866c90440508830, []int{4}
}

func (m *DegradedHealthyHost) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DegradedHealthyHost.Unmarshal(m, b)
}
func (m *DegradedHealthyHost) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DegradedHealthyHost.Marshal(b, m, deterministic)
}
func (m *DegradedHealthyHost) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DegradedHealthyHost.Merge(m, src)
}
func (m *DegradedHealthyHost) XXX_Size() int {
	return xxx_messageInfo_DegradedHealthyHost.Size(m)
}
func (m *DegradedHealthyHost) XXX_DiscardUnknown() {
	xxx_messageInfo_DegradedHealthyHost.DiscardUnknown(m)
}

var xxx_messageInfo_DegradedHealthyHost proto.InternalMessageInfo

type NoLongerDegradedHost struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NoLongerDegradedHost) Reset()         { *m = NoLongerDegradedHost{} }
func (m *NoLongerDegradedHost) String() string { return proto.CompactTextString(m) }
func (*NoLongerDegradedHost) ProtoMessage()    {}
func (*NoLongerDegradedHost) Descriptor() ([]byte, []int) {
	return fileDescriptor_e866c90440508830, []int{5}
}

func (m *NoLongerDegradedHost) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NoLongerDegradedHost.Unmarshal(m, b)
}
func (m *NoLongerDegradedHost) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NoLongerDegradedHost.Marshal(b, m, deterministic)
}
func (m *NoLongerDegradedHost) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NoLongerDegradedHost.Merge(m, src)
}
func (m *NoLongerDegradedHost) XXX_Size() int {
	return xxx_messageInfo_NoLongerDegradedHost.Size(m)
}
func (m *NoLongerDegradedHost) XXX_DiscardUnknown() {
	xxx_messageInfo_NoLongerDegradedHost.DiscardUnknown(m)
}

var xxx_messageInfo_NoLongerDegradedHost proto.InternalMessageInfo

func init() {
	proto.RegisterEnum("envoy.data.core.v2alpha.HealthCheckFailureType", HealthCheckFailureType_name, HealthCheckFailureType_value)
	proto.RegisterEnum("envoy.data.core.v2alpha.HealthCheckerType", HealthCheckerType_name, HealthCheckerType_value)
	proto.RegisterType((*HealthCheckEvent)(nil), "envoy.data.core.v2alpha.HealthCheckEvent")
	proto.RegisterType((*HealthCheckEjectUnhealthy)(nil), "envoy.data.core.v2alpha.HealthCheckEjectUnhealthy")
	proto.RegisterType((*HealthCheckAddHealthy)(nil), "envoy.data.core.v2alpha.HealthCheckAddHealthy")
	proto.RegisterType((*HealthCheckFailure)(nil), "envoy.data.core.v2alpha.HealthCheckFailure")
	proto.RegisterType((*DegradedHealthyHost)(nil), "envoy.data.core.v2alpha.DegradedHealthyHost")
	proto.RegisterType((*NoLongerDegradedHost)(nil), "envoy.data.core.v2alpha.NoLongerDegradedHost")
}

func init() {
	proto.RegisterFile("envoy/data/core/v2alpha/health_check_event.proto", fileDescriptor_e866c90440508830)
}

var fileDescriptor_e866c90440508830 = []byte{
	// 679 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x94, 0xdf, 0x6e, 0x12, 0x4f,
	0x14, 0xc7, 0x19, 0xfe, 0xb5, 0x1c, 0x9a, 0xfe, 0xb6, 0xd3, 0x52, 0xf8, 0x71, 0x21, 0x84, 0xc4,
	0xa4, 0xa9, 0x75, 0xd7, 0xe0, 0x8d, 0x89, 0x49, 0x13, 0xa0, 0x28, 0x8d, 0xa6, 0x92, 0xed, 0xaa,
	0x37, 0xc6, 0xcd, 0x94, 0x1d, 0xd8, 0xad, 0xcb, 0xce, 0x66, 0x77, 0x21, 0x12, 0xef, 0x7c, 0x02,
	0x6f, 0x7c, 0x87, 0x3e, 0x82, 0xf1, 0xaa, 0x6f, 0x62, 0xe2, 0x5d, 0xdf, 0xc2, 0xcc, 0xcc, 0x02,
	0x6d, 0x81, 0x04, 0x2f, 0xbc, 0x9b, 0x39, 0x33, 0xdf, 0xf3, 0x39, 0x73, 0xfe, 0x0c, 0x3c, 0xa1,
	0xde, 0x98, 0x4d, 0x34, 0x8b, 0x44, 0x44, 0xeb, 0xb1, 0x80, 0x6a, 0xe3, 0x3a, 0x71, 0x7d, 0x9b,
	0x68, 0x36, 0x25, 0x6e, 0x64, 0x9b, 0x3d, 0x9b, 0xf6, 0x3e, 0x99, 0x74, 0x4c, 0xbd, 0x48, 0xf5,
	0x03, 0x16, 0x31, 0x5c, 0x14, 0x0a, 0x95, 0x2b, 0x54, 0xae, 0x50, 0x63, 0x45, 0xb9, 0x22, 0x5d,
	0x11, 0xdf, 0xd1, 0xc6, 0x75, 0xe9, 0x8c, 0x58, 0x56, 0x40, 0xc3, 0x50, 0x2a, 0xcb, 0x95, 0x01,
	0x63, 0x03, 0x97, 0x6a, 0x62, 0x77, 0x31, 0xea, 0x6b, 0x91, 0x33, 0xa4, 0x61, 0x44, 0x86, 0x7e,
	0x7c, 0xa1, 0x38, 0x26, 0xae, 0x63, 0x91, 0x88, 0x6a, 0xd3, 0x45, 0x7c, 0xb0, 0x37, 0x60, 0x03,
	0x26, 0x96, 0x1a, 0x5f, 0x49, 0x6b, 0xed, 0x2a, 0x0b, 0x4a, 0x47, 0x84, 0xd9, 0xe2, 0x51, 0xb6,
	0x79, 0x90, 0xb8, 0x0f, 0xbb, 0xb7, 0x43, 0xa7, 0x81, 0x19, 0x4d, 0x7c, 0x5a, 0x42, 0x55, 0x74,
	0xb0, 0x5d, 0x3f, 0x54, 0x57, 0x04, 0xaf, 0xde, 0xf2, 0x43, 0x03, 0x63, 0xe2, 0xd3, 0x26, 0xfc,
	0xbc, 0xb9, 0x4e, 0x65, 0xbe, 0xa2, 0xa4, 0x82, 0xf4, 0x1d, 0xfb, 0xfe, 0x31, 0x56, 0x21, 0x6d,
	0xb3, 0x30, 0x2a, 0x25, 0xab, 0xe8, 0x20, 0x5f, 0x2f, 0xc7, 0x8e, 0x89, 0xef, 0xa8, 0xe3, 0xba,
	0x74, 0xdd, 0x90, 0x8f, 0xd7, 0xc5, 0x3d, 0x7c, 0x04, 0x5b, 0x3d, 0x77, 0x14, 0x46, 0x34, 0x30,
	0x3d, 0x32, 0xa4, 0xa5, 0x54, 0x15, 0x1d, 0xe4, 0x9a, 0x39, 0x0e, 0x49, 0x07, 0xc9, 0x2a, 0xd2,
	0xf3, 0xf1, 0xf1, 0x19, 0x19, 0x52, 0x6c, 0x43, 0x81, 0x5e, 0xd2, 0x5e, 0x64, 0x8e, 0x3c, 0x89,
	0x9e, 0xc8, 0x1a, 0x94, 0xd2, 0x02, 0x57, 0x5f, 0xe7, 0x1d, 0x6d, 0xee, 0xe0, 0xed, 0x54, 0xdf,
	0x49, 0xe8, 0xbb, 0xf4, 0x8e, 0x45, 0xe6, 0xeb, 0x03, 0xec, 0x10, 0xcb, 0x32, 0xef, 0x52, 0x32,
	0x82, 0xa2, 0xae, 0x43, 0x69, 0x58, 0x56, 0x67, 0x46, 0xf8, 0x8f, 0xcc, 0x76, 0xd2, 0xfb, 0x25,
	0x94, 0xef, 0x34, 0x52, 0x9f, 0x38, 0xee, 0x28, 0xa0, 0x31, 0x66, 0x43, 0x60, 0x1e, 0xad, 0x83,
	0x79, 0x21, 0x85, 0x9d, 0x84, 0x5e, 0xb4, 0x17, 0xac, 0x92, 0x75, 0x01, 0x05, 0x8b, 0x0e, 0x02,
	0x62, 0xd1, 0xf9, 0x73, 0x44, 0x89, 0x36, 0x05, 0xe6, 0x68, 0x25, 0xe6, 0x24, 0x56, 0x4d, 0xdf,
	0xc1, 0xc2, 0x88, 0x67, 0xcb, 0x5a, 0x34, 0xe3, 0x3e, 0x14, 0x3d, 0x66, 0xba, 0xcc, 0x1b, 0xd0,
	0xc0, 0x9c, 0xd3, 0x38, 0x25, 0x27, 0x28, 0x8f, 0x57, 0x52, 0xce, 0xd8, 0x6b, 0x21, 0x9b, 0xd1,
	0x24, 0x66, 0xcf, 0x5b, 0x62, 0xc7, 0xc7, 0x90, 0x9b, 0x0d, 0x47, 0x29, 0x1b, 0xb7, 0x98, 0x1c,
	0x1f, 0x75, 0x3a, 0x3e, 0xaa, 0x31, 0xbd, 0xd1, 0x4c, 0x7f, 0xfb, 0x55, 0x41, 0xfa, 0x5c, 0xd2,
	0xdc, 0x86, 0x8c, 0x48, 0x31, 0xce, 0xfc, 0xb8, 0xb9, 0x4e, 0xa1, 0xda, 0x17, 0xf8, 0x7f, 0x65,
	0x67, 0xe0, 0x8f, 0xb0, 0x35, 0xad, 0xcb, 0xad, 0x59, 0xd1, 0xfe, 0xa2, 0x2c, 0x0b, 0x03, 0x93,
	0xef, 0xcf, 0x0f, 0x6a, 0xcf, 0xa0, 0xb0, 0xb4, 0x61, 0x70, 0x05, 0xf2, 0x7d, 0x27, 0x08, 0x23,
	0xd9, 0x1c, 0x82, 0xbb, 0xa9, 0x83, 0x30, 0x89, 0xab, 0xb5, 0xef, 0x08, 0xf0, 0x22, 0xed, 0x5f,
	0x07, 0x7c, 0x3f, 0xae, 0xe4, 0x42, 0x5c, 0x05, 0xd8, 0x5d, 0xd2, 0x34, 0xb5, 0x7d, 0xd8, 0x5b,
	0x56, 0xe5, 0xc3, 0x63, 0xd8, 0x5f, 0x1e, 0x02, 0x06, 0xc8, 0x36, 0x5a, 0xc6, 0xe9, 0xbb, 0xb6,
	0x92, 0xc0, 0x79, 0xd8, 0xe8, 0x36, 0xce, 0xcf, 0xf9, 0x06, 0xf1, 0xcd, 0x59, 0xdb, 0x78, 0xff,
	0x46, 0x7f, 0xa5, 0x24, 0x0f, 0x9f, 0xc3, 0xce, 0xc2, 0xff, 0x84, 0x37, 0x21, 0xdd, 0x31, 0x8c,
	0xae, 0x92, 0xc0, 0x1b, 0x90, 0x32, 0x5a, 0x5d, 0x05, 0x71, 0xd3, 0x4b, 0xbd, 0xdb, 0x52, 0x92,
	0x38, 0x07, 0x19, 0xbd, 0x7d, 0x72, 0x7a, 0xae, 0xa4, 0x9a, 0x27, 0x57, 0xbf, 0x1f, 0x20, 0x78,
	0xe8, 0x30, 0x99, 0x1e, 0x3f, 0x60, 0x9f, 0x27, 0xab, 0x32, 0xd5, 0x2c, 0xdc, 0xff, 0x4f, 0xbb,
	0xbc, 0xd9, 0xba, 0xe8, 0x22, 0x2b, 0xba, 0xee, 0xe9, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x15,
	0x8d, 0x94, 0x7f, 0x30, 0x06, 0x00, 0x00,
}