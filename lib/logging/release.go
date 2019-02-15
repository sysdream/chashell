// +build !debug


package logging

func Debug(fmt string, args ...interface{}) { }
func Printf(fmt string, args ...interface{}) { }
func Fatal(fmt string, args ...interface{}) { }
func Println(v ...interface{}) { }
func Fatalf(fmt string, args ...interface{}) {}