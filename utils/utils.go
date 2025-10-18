package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)


func GetFilenName() (string, string, error) {
	var inputFile string
	var outputFile string
	fmt.Println("Provide the path to the file you want to encrypt: ")
	_, err := fmt.Scan(&inputFile)
	if err != nil {
		newErr := fmt.Sprint("Error reading input: ", err)
		return "", "", errors.New(newErr)
	}

	fmt.Println("Provide the output file's name (leave empty for default): ")
	_, err = fmt.Scan(&outputFile)
	if err != nil {
		newErr := fmt.Sprint("Error reading input: ", err)
		return "", "", errors.New(newErr)
	}

	return inputFile, outputFile, nil
}


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
