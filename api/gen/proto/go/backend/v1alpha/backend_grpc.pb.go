// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: teleport/backend/v1alpha/backend.proto

package backendv1alpha

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	BackendService_Write_FullMethodName       = "/teleport.backend.v1alpha.BackendService/Write"
	BackendService_MultiWrite_FullMethodName  = "/teleport.backend.v1alpha.BackendService/MultiWrite"
	BackendService_DeleteRange_FullMethodName = "/teleport.backend.v1alpha.BackendService/DeleteRange"
	BackendService_Read_FullMethodName        = "/teleport.backend.v1alpha.BackendService/Read"
)

// BackendServiceClient is the client API for BackendService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BackendServiceClient interface {
	// TODO
	Write(ctx context.Context, in *WriteRequest, opts ...grpc.CallOption) (*WriteResponse, error)
	// TODO
	MultiWrite(ctx context.Context, in *MultiWriteRequest, opts ...grpc.CallOption) (*MultiWriteResponse, error)
	// TODO
	DeleteRange(ctx context.Context, in *DeleteRangeRequest, opts ...grpc.CallOption) (*DeleteRangeResponse, error)
	// TODO
	Read(ctx context.Context, in *ReadRequest, opts ...grpc.CallOption) (*ReadResponse, error)
}

type backendServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewBackendServiceClient(cc grpc.ClientConnInterface) BackendServiceClient {
	return &backendServiceClient{cc}
}

func (c *backendServiceClient) Write(ctx context.Context, in *WriteRequest, opts ...grpc.CallOption) (*WriteResponse, error) {
	out := new(WriteResponse)
	err := c.cc.Invoke(ctx, BackendService_Write_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *backendServiceClient) MultiWrite(ctx context.Context, in *MultiWriteRequest, opts ...grpc.CallOption) (*MultiWriteResponse, error) {
	out := new(MultiWriteResponse)
	err := c.cc.Invoke(ctx, BackendService_MultiWrite_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *backendServiceClient) DeleteRange(ctx context.Context, in *DeleteRangeRequest, opts ...grpc.CallOption) (*DeleteRangeResponse, error) {
	out := new(DeleteRangeResponse)
	err := c.cc.Invoke(ctx, BackendService_DeleteRange_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *backendServiceClient) Read(ctx context.Context, in *ReadRequest, opts ...grpc.CallOption) (*ReadResponse, error) {
	out := new(ReadResponse)
	err := c.cc.Invoke(ctx, BackendService_Read_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BackendServiceServer is the server API for BackendService service.
// All implementations must embed UnimplementedBackendServiceServer
// for forward compatibility
type BackendServiceServer interface {
	// TODO
	Write(context.Context, *WriteRequest) (*WriteResponse, error)
	// TODO
	MultiWrite(context.Context, *MultiWriteRequest) (*MultiWriteResponse, error)
	// TODO
	DeleteRange(context.Context, *DeleteRangeRequest) (*DeleteRangeResponse, error)
	// TODO
	Read(context.Context, *ReadRequest) (*ReadResponse, error)
	mustEmbedUnimplementedBackendServiceServer()
}

// UnimplementedBackendServiceServer must be embedded to have forward compatible implementations.
type UnimplementedBackendServiceServer struct {
}

func (UnimplementedBackendServiceServer) Write(context.Context, *WriteRequest) (*WriteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Write not implemented")
}
func (UnimplementedBackendServiceServer) MultiWrite(context.Context, *MultiWriteRequest) (*MultiWriteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method MultiWrite not implemented")
}
func (UnimplementedBackendServiceServer) DeleteRange(context.Context, *DeleteRangeRequest) (*DeleteRangeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteRange not implemented")
}
func (UnimplementedBackendServiceServer) Read(context.Context, *ReadRequest) (*ReadResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Read not implemented")
}
func (UnimplementedBackendServiceServer) mustEmbedUnimplementedBackendServiceServer() {}

// UnsafeBackendServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BackendServiceServer will
// result in compilation errors.
type UnsafeBackendServiceServer interface {
	mustEmbedUnimplementedBackendServiceServer()
}

func RegisterBackendServiceServer(s grpc.ServiceRegistrar, srv BackendServiceServer) {
	s.RegisterService(&BackendService_ServiceDesc, srv)
}

func _BackendService_Write_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(WriteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).Write(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_Write_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).Write(ctx, req.(*WriteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BackendService_MultiWrite_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(MultiWriteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).MultiWrite(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_MultiWrite_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).MultiWrite(ctx, req.(*MultiWriteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BackendService_DeleteRange_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteRangeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).DeleteRange(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_DeleteRange_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).DeleteRange(ctx, req.(*DeleteRangeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _BackendService_Read_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReadRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BackendServiceServer).Read(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: BackendService_Read_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BackendServiceServer).Read(ctx, req.(*ReadRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// BackendService_ServiceDesc is the grpc.ServiceDesc for BackendService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var BackendService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.backend.v1alpha.BackendService",
	HandlerType: (*BackendServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Write",
			Handler:    _BackendService_Write_Handler,
		},
		{
			MethodName: "MultiWrite",
			Handler:    _BackendService_MultiWrite_Handler,
		},
		{
			MethodName: "DeleteRange",
			Handler:    _BackendService_DeleteRange_Handler,
		},
		{
			MethodName: "Read",
			Handler:    _BackendService_Read_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/backend/v1alpha/backend.proto",
}
