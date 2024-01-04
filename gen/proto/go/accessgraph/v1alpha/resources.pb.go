// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: accessgraph/v1alpha/resources.proto

package accessgraphv1alpha

import (
	v1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/accesslist/v1"
	types "github.com/gravitational/teleport/api/types"
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

// ResourceList is a list of resources to send to the access graph.
type ResourceList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Resources []*ResourceEntry `protobuf:"bytes,1,rep,name=resources,proto3" json:"resources,omitempty"`
}

func (x *ResourceList) Reset() {
	*x = ResourceList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceList) ProtoMessage() {}

func (x *ResourceList) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceList.ProtoReflect.Descriptor instead.
func (*ResourceList) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_resources_proto_rawDescGZIP(), []int{0}
}

func (x *ResourceList) GetResources() []*ResourceEntry {
	if x != nil {
		return x.Resources
	}
	return nil
}

// ResourceHeaderList is a list of resource headers to send to the access graph.
type ResourceHeaderList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Resources []*types.ResourceHeader `protobuf:"bytes,1,rep,name=resources,proto3" json:"resources,omitempty"`
}

func (x *ResourceHeaderList) Reset() {
	*x = ResourceHeaderList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceHeaderList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceHeaderList) ProtoMessage() {}

func (x *ResourceHeaderList) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceHeaderList.ProtoReflect.Descriptor instead.
func (*ResourceHeaderList) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_resources_proto_rawDescGZIP(), []int{1}
}

func (x *ResourceHeaderList) GetResources() []*types.ResourceHeader {
	if x != nil {
		return x.Resources
	}
	return nil
}

// AccessListsMembers is the request to declare users as members of access lists.
type AccessListsMembers struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// members is the list of members to add to access lists.
	Members []*v1.Member `protobuf:"bytes,1,rep,name=members,proto3" json:"members,omitempty"`
}

func (x *AccessListsMembers) Reset() {
	*x = AccessListsMembers{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessListsMembers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessListsMembers) ProtoMessage() {}

func (x *AccessListsMembers) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessListsMembers.ProtoReflect.Descriptor instead.
func (*AccessListsMembers) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_resources_proto_rawDescGZIP(), []int{2}
}

func (x *AccessListsMembers) GetMembers() []*v1.Member {
	if x != nil {
		return x.Members
	}
	return nil
}

// ExcludeAccessListsMembers is the request to exclude users from access lists.
type ExcludeAccessListsMembers struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Members []*ExcludeAccessListMember `protobuf:"bytes,1,rep,name=members,proto3" json:"members,omitempty"`
}

func (x *ExcludeAccessListsMembers) Reset() {
	*x = ExcludeAccessListsMembers{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExcludeAccessListsMembers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExcludeAccessListsMembers) ProtoMessage() {}

func (x *ExcludeAccessListsMembers) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExcludeAccessListsMembers.ProtoReflect.Descriptor instead.
func (*ExcludeAccessListsMembers) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_resources_proto_rawDescGZIP(), []int{3}
}

func (x *ExcludeAccessListsMembers) GetMembers() []*ExcludeAccessListMember {
	if x != nil {
		return x.Members
	}
	return nil
}

// ExcludeAccessListMember is the request to exclude a user from an access list.
type ExcludeAccessListMember struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccessList string `protobuf:"bytes,1,opt,name=access_list,json=accessList,proto3" json:"access_list,omitempty"`
	Username   string `protobuf:"bytes,2,opt,name=username,proto3" json:"username,omitempty"`
}

func (x *ExcludeAccessListMember) Reset() {
	*x = ExcludeAccessListMember{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExcludeAccessListMember) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExcludeAccessListMember) ProtoMessage() {}

func (x *ExcludeAccessListMember) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExcludeAccessListMember.ProtoReflect.Descriptor instead.
func (*ExcludeAccessListMember) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_resources_proto_rawDescGZIP(), []int{4}
}

func (x *ExcludeAccessListMember) GetAccessList() string {
	if x != nil {
		return x.AccessList
	}
	return ""
}

func (x *ExcludeAccessListMember) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

// ResourceEntry is a wrapper for the supported resource types.
type ResourceEntry struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Resource:
	//
	//	*ResourceEntry_User
	//	*ResourceEntry_Role
	//	*ResourceEntry_Server
	//	*ResourceEntry_AccessRequest
	//	*ResourceEntry_KubernetesServer
	//	*ResourceEntry_AppServer
	//	*ResourceEntry_DatabaseServer
	//	*ResourceEntry_WindowsDesktop
	//	*ResourceEntry_AccessList
	Resource isResourceEntry_Resource `protobuf_oneof:"resource"`
}

func (x *ResourceEntry) Reset() {
	*x = ResourceEntry{}
	if protoimpl.UnsafeEnabled {
		mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ResourceEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResourceEntry) ProtoMessage() {}

func (x *ResourceEntry) ProtoReflect() protoreflect.Message {
	mi := &file_accessgraph_v1alpha_resources_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResourceEntry.ProtoReflect.Descriptor instead.
func (*ResourceEntry) Descriptor() ([]byte, []int) {
	return file_accessgraph_v1alpha_resources_proto_rawDescGZIP(), []int{5}
}

func (m *ResourceEntry) GetResource() isResourceEntry_Resource {
	if m != nil {
		return m.Resource
	}
	return nil
}

func (x *ResourceEntry) GetUser() *types.UserV2 {
	if x, ok := x.GetResource().(*ResourceEntry_User); ok {
		return x.User
	}
	return nil
}

func (x *ResourceEntry) GetRole() *types.RoleV6 {
	if x, ok := x.GetResource().(*ResourceEntry_Role); ok {
		return x.Role
	}
	return nil
}

func (x *ResourceEntry) GetServer() *types.ServerV2 {
	if x, ok := x.GetResource().(*ResourceEntry_Server); ok {
		return x.Server
	}
	return nil
}

func (x *ResourceEntry) GetAccessRequest() *types.AccessRequestV3 {
	if x, ok := x.GetResource().(*ResourceEntry_AccessRequest); ok {
		return x.AccessRequest
	}
	return nil
}

func (x *ResourceEntry) GetKubernetesServer() *types.KubernetesServerV3 {
	if x, ok := x.GetResource().(*ResourceEntry_KubernetesServer); ok {
		return x.KubernetesServer
	}
	return nil
}

func (x *ResourceEntry) GetAppServer() *types.AppServerV3 {
	if x, ok := x.GetResource().(*ResourceEntry_AppServer); ok {
		return x.AppServer
	}
	return nil
}

func (x *ResourceEntry) GetDatabaseServer() *types.DatabaseServerV3 {
	if x, ok := x.GetResource().(*ResourceEntry_DatabaseServer); ok {
		return x.DatabaseServer
	}
	return nil
}

func (x *ResourceEntry) GetWindowsDesktop() *types.WindowsDesktopV3 {
	if x, ok := x.GetResource().(*ResourceEntry_WindowsDesktop); ok {
		return x.WindowsDesktop
	}
	return nil
}

func (x *ResourceEntry) GetAccessList() *v1.AccessList {
	if x, ok := x.GetResource().(*ResourceEntry_AccessList); ok {
		return x.AccessList
	}
	return nil
}

type isResourceEntry_Resource interface {
	isResourceEntry_Resource()
}

type ResourceEntry_User struct {
	// user is a user resource
	User *types.UserV2 `protobuf:"bytes,1,opt,name=user,proto3,oneof"`
}

type ResourceEntry_Role struct {
	// role is a role resource
	Role *types.RoleV6 `protobuf:"bytes,2,opt,name=role,proto3,oneof"`
}

type ResourceEntry_Server struct {
	// server is a node/server resource
	Server *types.ServerV2 `protobuf:"bytes,3,opt,name=server,proto3,oneof"`
}

type ResourceEntry_AccessRequest struct {
	// access_request is a resource for access requests
	AccessRequest *types.AccessRequestV3 `protobuf:"bytes,4,opt,name=access_request,json=accessRequest,proto3,oneof"`
}

type ResourceEntry_KubernetesServer struct {
	// kubernetes_server is a kubernetes server resource
	KubernetesServer *types.KubernetesServerV3 `protobuf:"bytes,5,opt,name=kubernetes_server,json=kubernetesServer,proto3,oneof"`
}

type ResourceEntry_AppServer struct {
	// app_server is an application server resource
	AppServer *types.AppServerV3 `protobuf:"bytes,6,opt,name=app_server,json=appServer,proto3,oneof"`
}

type ResourceEntry_DatabaseServer struct {
	// database_server is a database server resource
	DatabaseServer *types.DatabaseServerV3 `protobuf:"bytes,7,opt,name=database_server,json=databaseServer,proto3,oneof"`
}

type ResourceEntry_WindowsDesktop struct {
	// windows_desktop is a resource for Windows desktop host.
	WindowsDesktop *types.WindowsDesktopV3 `protobuf:"bytes,8,opt,name=windows_desktop,json=windowsDesktop,proto3,oneof"`
}

type ResourceEntry_AccessList struct {
	// access_list is a resource for access lists.
	AccessList *v1.AccessList `protobuf:"bytes,9,opt,name=access_list,json=accessList,proto3,oneof"`
}

func (*ResourceEntry_User) isResourceEntry_Resource() {}

func (*ResourceEntry_Role) isResourceEntry_Resource() {}

func (*ResourceEntry_Server) isResourceEntry_Resource() {}

func (*ResourceEntry_AccessRequest) isResourceEntry_Resource() {}

func (*ResourceEntry_KubernetesServer) isResourceEntry_Resource() {}

func (*ResourceEntry_AppServer) isResourceEntry_Resource() {}

func (*ResourceEntry_DatabaseServer) isResourceEntry_Resource() {}

func (*ResourceEntry_WindowsDesktop) isResourceEntry_Resource() {}

func (*ResourceEntry_AccessList) isResourceEntry_Resource() {}

var File_accessgraph_v1alpha_resources_proto protoreflect.FileDescriptor

var file_accessgraph_v1alpha_resources_proto_rawDesc = []byte{
	0x0a, 0x23, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2f, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x13, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61,
	0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x27, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2f,
	0x76, 0x31, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x65,
	0x67, 0x61, 0x63, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x50, 0x0a, 0x0c, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x40, 0x0a, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e,
	0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x09, 0x72,
	0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x22, 0x49, 0x0a, 0x12, 0x52, 0x65, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x33,
	0x0a, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x15, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x09, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x73, 0x22, 0x4e, 0x0a, 0x12, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73,
	0x74, 0x73, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x12, 0x38, 0x0a, 0x07, 0x6d, 0x65, 0x6d,
	0x62, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74,
	0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x52, 0x07, 0x6d, 0x65, 0x6d, 0x62,
	0x65, 0x72, 0x73, 0x22, 0x63, 0x0a, 0x19, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x41, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x73, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73,
	0x12, 0x46, 0x0a, 0x07, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x2c, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68, 0x2e,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x45, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x41,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x52,
	0x07, 0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x22, 0x56, 0x0a, 0x17, 0x45, 0x78, 0x63, 0x6c,
	0x75, 0x64, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x4d, 0x65, 0x6d,
	0x62, 0x65, 0x72, 0x12, 0x1f, 0x0a, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6c, 0x69,
	0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x4c, 0x69, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65,
	0x22, 0x9f, 0x04, 0x0a, 0x0d, 0x52, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x23, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x0d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x56, 0x32, 0x48,
	0x00, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x12, 0x23, 0x0a, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x52, 0x6f,
	0x6c, 0x65, 0x56, 0x36, 0x48, 0x00, 0x52, 0x04, 0x72, 0x6f, 0x6c, 0x65, 0x12, 0x29, 0x0a, 0x06,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x56, 0x32, 0x48, 0x00, 0x52,
	0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x3f, 0x0a, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x5f, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x16, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x56, 0x33, 0x48, 0x00, 0x52, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x48, 0x0a, 0x11, 0x6b, 0x75, 0x62, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x65, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x4b, 0x75, 0x62, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x65, 0x73, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x56, 0x33, 0x48, 0x00,
	0x52, 0x10, 0x6b, 0x75, 0x62, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x65, 0x73, 0x53, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x12, 0x33, 0x0a, 0x0a, 0x61, 0x70, 0x70, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x41,
	0x70, 0x70, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x56, 0x33, 0x48, 0x00, 0x52, 0x09, 0x61, 0x70,
	0x70, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x42, 0x0a, 0x0f, 0x64, 0x61, 0x74, 0x61, 0x62,
	0x61, 0x73, 0x65, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x17, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73,
	0x65, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x56, 0x33, 0x48, 0x00, 0x52, 0x0e, 0x64, 0x61, 0x74,
	0x61, 0x62, 0x61, 0x73, 0x65, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x42, 0x0a, 0x0f, 0x77,
	0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5f, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x57, 0x69, 0x6e,
	0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x56, 0x33, 0x48, 0x00, 0x52,
	0x0e, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x44, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x12,
	0x45, 0x0a, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x09,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6c, 0x69, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0a, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x42, 0x0a, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x42, 0x57, 0x5a, 0x55, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67, 0x72, 0x61, 0x70, 0x68,
	0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x3b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x67,
	0x72, 0x61, 0x70, 0x68, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_accessgraph_v1alpha_resources_proto_rawDescOnce sync.Once
	file_accessgraph_v1alpha_resources_proto_rawDescData = file_accessgraph_v1alpha_resources_proto_rawDesc
)

func file_accessgraph_v1alpha_resources_proto_rawDescGZIP() []byte {
	file_accessgraph_v1alpha_resources_proto_rawDescOnce.Do(func() {
		file_accessgraph_v1alpha_resources_proto_rawDescData = protoimpl.X.CompressGZIP(file_accessgraph_v1alpha_resources_proto_rawDescData)
	})
	return file_accessgraph_v1alpha_resources_proto_rawDescData
}

var file_accessgraph_v1alpha_resources_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_accessgraph_v1alpha_resources_proto_goTypes = []interface{}{
	(*ResourceList)(nil),              // 0: accessgraph.v1alpha.ResourceList
	(*ResourceHeaderList)(nil),        // 1: accessgraph.v1alpha.ResourceHeaderList
	(*AccessListsMembers)(nil),        // 2: accessgraph.v1alpha.AccessListsMembers
	(*ExcludeAccessListsMembers)(nil), // 3: accessgraph.v1alpha.ExcludeAccessListsMembers
	(*ExcludeAccessListMember)(nil),   // 4: accessgraph.v1alpha.ExcludeAccessListMember
	(*ResourceEntry)(nil),             // 5: accessgraph.v1alpha.ResourceEntry
	(*types.ResourceHeader)(nil),      // 6: types.ResourceHeader
	(*v1.Member)(nil),                 // 7: teleport.accesslist.v1.Member
	(*types.UserV2)(nil),              // 8: types.UserV2
	(*types.RoleV6)(nil),              // 9: types.RoleV6
	(*types.ServerV2)(nil),            // 10: types.ServerV2
	(*types.AccessRequestV3)(nil),     // 11: types.AccessRequestV3
	(*types.KubernetesServerV3)(nil),  // 12: types.KubernetesServerV3
	(*types.AppServerV3)(nil),         // 13: types.AppServerV3
	(*types.DatabaseServerV3)(nil),    // 14: types.DatabaseServerV3
	(*types.WindowsDesktopV3)(nil),    // 15: types.WindowsDesktopV3
	(*v1.AccessList)(nil),             // 16: teleport.accesslist.v1.AccessList
}
var file_accessgraph_v1alpha_resources_proto_depIdxs = []int32{
	5,  // 0: accessgraph.v1alpha.ResourceList.resources:type_name -> accessgraph.v1alpha.ResourceEntry
	6,  // 1: accessgraph.v1alpha.ResourceHeaderList.resources:type_name -> types.ResourceHeader
	7,  // 2: accessgraph.v1alpha.AccessListsMembers.members:type_name -> teleport.accesslist.v1.Member
	4,  // 3: accessgraph.v1alpha.ExcludeAccessListsMembers.members:type_name -> accessgraph.v1alpha.ExcludeAccessListMember
	8,  // 4: accessgraph.v1alpha.ResourceEntry.user:type_name -> types.UserV2
	9,  // 5: accessgraph.v1alpha.ResourceEntry.role:type_name -> types.RoleV6
	10, // 6: accessgraph.v1alpha.ResourceEntry.server:type_name -> types.ServerV2
	11, // 7: accessgraph.v1alpha.ResourceEntry.access_request:type_name -> types.AccessRequestV3
	12, // 8: accessgraph.v1alpha.ResourceEntry.kubernetes_server:type_name -> types.KubernetesServerV3
	13, // 9: accessgraph.v1alpha.ResourceEntry.app_server:type_name -> types.AppServerV3
	14, // 10: accessgraph.v1alpha.ResourceEntry.database_server:type_name -> types.DatabaseServerV3
	15, // 11: accessgraph.v1alpha.ResourceEntry.windows_desktop:type_name -> types.WindowsDesktopV3
	16, // 12: accessgraph.v1alpha.ResourceEntry.access_list:type_name -> teleport.accesslist.v1.AccessList
	13, // [13:13] is the sub-list for method output_type
	13, // [13:13] is the sub-list for method input_type
	13, // [13:13] is the sub-list for extension type_name
	13, // [13:13] is the sub-list for extension extendee
	0,  // [0:13] is the sub-list for field type_name
}

func init() { file_accessgraph_v1alpha_resources_proto_init() }
func file_accessgraph_v1alpha_resources_proto_init() {
	if File_accessgraph_v1alpha_resources_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_accessgraph_v1alpha_resources_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceList); i {
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
		file_accessgraph_v1alpha_resources_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceHeaderList); i {
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
		file_accessgraph_v1alpha_resources_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessListsMembers); i {
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
		file_accessgraph_v1alpha_resources_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExcludeAccessListsMembers); i {
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
		file_accessgraph_v1alpha_resources_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExcludeAccessListMember); i {
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
		file_accessgraph_v1alpha_resources_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ResourceEntry); i {
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
	file_accessgraph_v1alpha_resources_proto_msgTypes[5].OneofWrappers = []interface{}{
		(*ResourceEntry_User)(nil),
		(*ResourceEntry_Role)(nil),
		(*ResourceEntry_Server)(nil),
		(*ResourceEntry_AccessRequest)(nil),
		(*ResourceEntry_KubernetesServer)(nil),
		(*ResourceEntry_AppServer)(nil),
		(*ResourceEntry_DatabaseServer)(nil),
		(*ResourceEntry_WindowsDesktop)(nil),
		(*ResourceEntry_AccessList)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_accessgraph_v1alpha_resources_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_accessgraph_v1alpha_resources_proto_goTypes,
		DependencyIndexes: file_accessgraph_v1alpha_resources_proto_depIdxs,
		MessageInfos:      file_accessgraph_v1alpha_resources_proto_msgTypes,
	}.Build()
	File_accessgraph_v1alpha_resources_proto = out.File
	file_accessgraph_v1alpha_resources_proto_rawDesc = nil
	file_accessgraph_v1alpha_resources_proto_goTypes = nil
	file_accessgraph_v1alpha_resources_proto_depIdxs = nil
}
