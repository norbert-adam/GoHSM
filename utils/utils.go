package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

func ReadFile(path string, data []byte) ([]byte, error) {
		
	file, err := os.Open(path)
	if err != nil {
		newErr := fmt.Sprint("Error opening the file: ", err)
		return nil, errors.New(newErr)
	}

	buf := make([]byte, 4096)
	reader := bufio.NewReader(file)
	
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}

		if err != nil {
			if err == io.EOF{
				break
			}
			newErr := fmt.Sprint("Error reading file's contents: ", err)
			return nil, errors.New(newErr)
		}
	}
	return data, nil
}

func WriteFile(path string, data []byte) (error) {
	var outputName string
	if path == "" {
		outputName = fmt.Sprintf("out_%s", path)
	} else {
		outputName = path
	}

	outputFile, err := os.Create(outputName)
	if err != nil {
		newErr := fmt.Sprintf("Error creating output file %s: %s", outputName, err)
		return errors.New(newErr)
	}

	writer := bufio.NewWriter(outputFile)
	defer writer.Flush()

	_, err = writer.Write(data)
	if err != nil {
		newErr := fmt.Sprintf("Error writing to output file %s: %s", outputName, err)
		return errors.New(newErr)
	}
	
	return nil
}
