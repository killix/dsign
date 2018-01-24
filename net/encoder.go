package net

import (
	"fmt"
	"reflect"

	"github.com/dedis/kyber"
	"github.com/dedis/protobuf"
	"github.com/nikkolasg/dsign/key"
)

// Encoder role is to marshal and unmarshal messages from the network layer.
// Different encoding techniques can be easily used with this generic
// interface.
type Encoder interface {
	// Marshal takes a  message and returns the corresponding encoding.
	// The msg must be a POINTER to the message.
	Marshal(msg interface{}) ([]byte, error)
	// Unmarshal takes a slice of bytes and returns the corresponding message
	// and its type. The caller is responsible to give the right slice length so
	// the Encoder can decode. It returns a POINTER to the message.
	Unmarshal([]byte) (interface{}, error)
}

// SingleProtoEncoder is a struct that encodes and decodes a unique message using
// protobuf.  This encoder is useful when the whole message set can be contained
// in a single wrapper struct that protobuf can decode.
type SingleProtoEncoder struct {
	t    reflect.Type
	cons protobuf.Constructors
}

// NewSingleProtoEncoder returns a SingleProtoEncoder that can encode/decode
// only the given type of struct given in argument.
func NewSingleProtoEncoder(msg interface{}) *SingleProtoEncoder {
	t := getValueType(msg)
	return &SingleProtoEncoder{t, defaultConstructors(key.Curve)}
}

// Marshal implements interface
func (m *SingleProtoEncoder) Marshal(msg interface{}) ([]byte, error) {
	if t := getValueType(msg); t != m.t {
		return nil, fmt.Errorf("monoencoder: can't encode %s", t.String())
	}
	return protobuf.Encode(msg)
}

// Unmarshal implements interface
func (m *SingleProtoEncoder) Unmarshal(buff []byte) (interface{}, error) {
	ptrVal := reflect.New(m.t)
	ptr := ptrVal.Interface()
	constructors := defaultConstructors(key.Curve)
	if err := protobuf.DecodeWithConstructors(buff, ptr, constructors); err != nil {
		return nil, err
	}

	return ptrVal.Interface(), nil
}

// DefaultConstructors gives a default constructor for protobuf out of the global suite
func defaultConstructors(g kyber.Group) protobuf.Constructors {
	constructors := make(protobuf.Constructors)
	var point kyber.Point
	var secret kyber.Scalar
	constructors[reflect.TypeOf(&point).Elem()] = func() interface{} { return g.Point() }
	constructors[reflect.TypeOf(&secret).Elem()] = func() interface{} { return g.Scalar() }
	return constructors
}

func getValueType(m interface{}) reflect.Type {
	val := reflect.ValueOf(m)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	return val.Type()
}
