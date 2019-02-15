// +build debug

package logging

import "log"

func Debug(fmt string, args ...interface{}) {
	log.Printf(fmt, args...)
}

func Printf(fmt string, args ...interface{}) {
	log.Printf(fmt, args...)
}

func Fatal(args ...interface{}) {
	log.Fatal(args...)
}

func Fatalf(fmt string, args ...interface{}) {
	log.Fatalf(fmt, args...)
}

func Println(v ...interface{}){
	log.Println(v...)
}