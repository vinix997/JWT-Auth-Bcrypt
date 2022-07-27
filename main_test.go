package main

import (
	"io/ioutil"
	"testing"
	"ws/service"

	"github.com/stretchr/testify/require"
)

func TestGenerateWeatherStatusFile(t *testing.T) {
	service.NewUserService().Register()
	type args struct {
		data Weather
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
		{name: "test", args: args{data: Weather{Status: Status{Water: 10, Wind: 5}}}},
		{name: "test1", args: args{data: Weather{Status: Status{Water: 12, Wind: 4}}}},
		{name: "test2", args: args{data: Weather{Status: Status{Water: 7, Wind: 8}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			GenerateWeatherStatusFile(tt.args.data)
			file, err := ioutil.ReadFile(JsonPath)
			require.Nil(t, err)
			require.NotNil(t, file)
		})
	}

}
