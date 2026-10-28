package av_test

import (
	"errors"
	"io/fs"
	"log"
	"os"

	"github.com/oneryx/av"
)

func ExampleRead() {
	vars, err := av.Read("") // ./.env.age, identities found like av does
	if err != nil {
		log.Fatal(err)
	}
	_ = vars["DATABASE_URL"]
}

func ExampleLoad() {
	// Use the file if it's there; in production the real environment may
	// provide everything.
	err := av.Load("config/dev.env.age", av.WithIdentityData([]byte(os.Getenv("AGE_KEY"))))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Fatal(err)
	}
}
