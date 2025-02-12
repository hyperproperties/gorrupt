package quick

import (
	"iter"
	"math"
	"math/rand/v2"
	"reflect"
	"unsafe"
)

func New[T any]() T {
	var value T
	concrete := reflect.ValueOf(&value).Elem()
	NewReflect(concrete)
	return value
}

func Iterator[T any]() iter.Seq[T] {
	return func(yield func(T) bool) {
		for {
			if !yield(New[T]()) {
				return
			}
		}
	}
}

func Iterator2[T any]() iter.Seq2[int, T] {
	return func(yield func(int, T) bool) {
		i := 0
		for value := range Iterator[T]() {
			if !yield(i, value) {
				return
			}
			i++
		}
	}
}

func Update[T any](value *T) {
	concrete := reflect.ValueOf(value).Elem()
	NewReflect(concrete)
}

func NewReflect(value reflect.Value) {
	switch kind := value.Kind(); kind {
	case reflect.Bool:
		value.SetBool(rand.Int()&1 == 0)
	case reflect.Float32:
		value.SetFloat(float64((rand.Float32()*2 - 1) * math.MaxFloat32))
	case reflect.Float64:
		value.SetFloat((rand.Float64()*2 - 1) * math.MaxFloat64)
	case reflect.Complex64:
		value.SetComplex(complex(float64(rand.Float32()), float64(rand.Float32())))
	case reflect.Complex128:
		value.SetComplex(complex(rand.Float64(), rand.Float64()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(rand.Int64())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		value.SetUint(rand.Uint64())
	case reflect.Slice:
		length := int(rand.Int32N(10)) // FIXME: Hints for lengths.
		newSlice := reflect.MakeSlice(value.Type(), length, length)
		for i := 0; i < length; i++ {
			NewReflect(newSlice.Index(i))
		}
		value.Set(newSlice)
	case reflect.Array:
		length := value.Len()
		for i := 0; i < length; i++ {
			NewReflect(value.Index(i))
		}
	case reflect.Struct:
		n := value.NumField()
		for i := 0; i < n; i++ {
			field := value.Field(i)
			if field.CanSet() {
				NewReflect(field)
			} else {
				fieldPtr := unsafe.Pointer(field.UnsafeAddr())
				unsafeField := reflect.NewAt(field.Type(), fieldPtr).Elem()
				NewReflect(unsafeField)
			}
		}
	case reflect.Ptr:
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		NewReflect(value.Elem())
	}
}

var USAlphabet = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func String(length int, alphabet ...rune) string {
	buffer := make([]rune, length)
    for i := range buffer {
        buffer[i] = alphabet[rand.IntN(len(alphabet))]
    }
    return string(buffer)
}