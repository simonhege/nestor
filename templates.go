package main

import (
	"embed"
	"html/template"
	"io"
	"os"
)

//go:embed templates/*
var fs embed.FS

var tmpl *template.Template

func init() {
	var err error
	tmpl, err = template.ParseFS(fs, "templates/*")
	if err != nil {
		panic(err)
	}
}

func executeTemplate(wr io.Writer, name string, data any) error {
	t := tmpl
	if os.Getenv("DEBUG_TEMPLATES") == "Y" {
		local, err := template.ParseGlob("templates/*")
		if err != nil {
			return err
		}
		t = local
	}
	return t.ExecuteTemplate(wr, name, data)
}
