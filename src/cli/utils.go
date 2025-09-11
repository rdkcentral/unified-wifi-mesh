package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/rdkcentral/unified-wifi-mesh/src/cli/etree"
)

func splitIntoLines(content string) []string {
    return strings.Split(content, "\n")
}

// convertJSONToNodes recursively converts a JSON data structure into etree.Node slice.
// It handles objects, arrays, strings, numbers, and boolean values.
//
// Parameters:
//   - data: interface{} containing unmarshaled JSON data
//
// Returns:
//   - []etree.Node: slice of nodes representing the JSON structure
//
// Example JSON input:
//
//	{
//	  "key1": "value1",
//	  "key2": {
//	    "nested": "value"
//	  },
//	  "key3": [1,2,3]
//	}
func convertJSONToNodes(data interface{}) []etree.Node {
	var nodes []etree.Node

	switch v := data.(type) {
	case map[string]interface{}:
		// Handle object
		for key, value := range v {
			node := etree.Node{
				Key:   key,
				Value: textinput.New(),
			}

			switch val := value.(type) {
			case map[string]interface{}:
				node.Type = etree.NodeTypeObject
				node.Children = convertJSONToNodes(val)
			case []interface{}:
				node.Type = etree.NodeTypeArrayObj
				node.Children = convertJSONToNodes(val)
			case string:
				node.Type = etree.NodeTypeString
				node.Value.Placeholder = val
			case float64:
				node.Type = etree.NodeTypeNumber
				node.Value.Placeholder = fmt.Sprintf("%v", val)
			case bool:
				if val {
					node.Type = etree.NodeTypeTrue
				} else {
					node.Type = etree.NodeTypeFalse
				}
				node.Value.Placeholder = fmt.Sprintf("%v", val)
			}
			nodes = append(nodes, node)
		}

	case []interface{}:
		// Handle array
		for _, value := range v {
			childNodes := convertJSONToNodes(value)
			nodes = append(nodes, childNodes...)
		}
	}

	return nodes
}

// readJSONFile reads a JSON file and converts its contents into an etree.Node structure.
// The function can handle any valid JSON file with nested objects and arrays.
//
// Parameters:
//   - filePath: string path to the JSON file
//
// Returns:
//   - []etree.Node: slice of nodes representing the JSON structure
//   - error: any error encountered during file reading or JSON parsing
//
// Example:
//
//	nodes, err := readJSONFile("config.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
func readJSONFile(filePath string) ([]etree.Node, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, err
	}

	nodes := convertJSONToNodes(jsonData)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes created from JSON")
	}

	return nodes, nil
}



// convertNodesToJSON converts an etree.Node structure back into a generic interface{}
// that can be marshaled to JSON. It handles objects, arrays, strings, numbers and booleans.
//
// Parameters:
//   - nodes: []etree.Node slice containing the tree structure to convert
//
// Returns:
//   - interface{}: generic data structure ready for JSON marshaling
//
// Example input:
//   nodes := []etree.Node{
//     {
//       Key: "root",
//       Type: etree.NodeTypeObject,
//       Children: []etree.Node{
//         {Key: "string", Type: etree.NodeTypeString, Value: "value"},
//         {Key: "number", Type: etree.NodeTypeNumber, Value: "42"},
//       },
//     },
//   }
func convertNodesToJSON(nodes []etree.Node) interface{} {
    if len(nodes) == 0 {
        return nil
    }

    // Handle single root node
    node := nodes[0]
    
    switch node.Type {
    case etree.NodeTypeObject:
        result := make(map[string]interface{})
        for _, child := range node.Children {
            value := child.Value.Value()
            if value == "" {
                value = child.Value.Placeholder
            }
            
            switch child.Type {
            case etree.NodeTypeObject, etree.NodeTypeArrayObj:
                result[child.Key] = convertNodesToJSON([]etree.Node{child})
            case etree.NodeTypeString:
                result[child.Key] = value
            case etree.NodeTypeNumber:
                if f, err := strconv.ParseFloat(value, 64); err == nil {
                    result[child.Key] = f
                }
            case etree.NodeTypeTrue:
                result[child.Key] = true
            case etree.NodeTypeFalse:
                result[child.Key] = false
            }
        }
        return result
        
    case etree.NodeTypeArrayObj:
        var result []interface{}
        for _, child := range node.Children {
            result = append(result, convertNodesToJSON([]etree.Node{child}))
        }
        return result
    }
    
    return nil
}



// readTextFileToNodes reads a text file, wraps its content in a JSON structure
// with the "URI" key, and converts it to etree.Node structure.
//
// Parameters:
//   - filePath: string path to the text file
//
// Returns:
//   - []etree.Node: slice of nodes representing the JSON structure with URI key
//   - error: any error encountered during file reading or conversion
//
// Example:
//   If text file contains "DPP:C:81/1:some-key-here;"
//   The resulting JSON structure will be:
//   {
//     "URI": "DPP:C:81/1:some-key-here;"
//   }
func readDPPUriTxtFileToNodes(filePath string) ([]etree.Node, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	// Trim whitespace/newlines from the content
	uriContent := strings.TrimSpace(string(content))

	// Create JSON structure with URI object containing URI key
	jsonData := map[string]interface{}{
		"URI": map[string]interface{}{
			"URI": uriContent,
		},
	}

	// Convert to nodes using existing function
	nodes := convertJSONToNodes(jsonData)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes created from text file content")
	}

	return nodes, nil
}

// writeJSONFile writes an etree.Node structure to a JSON file.
// The nodes are first converted to a generic interface{} and then marshaled to JSON
// with proper indentation. The file is created with 0644 permissions.
//
// Parameters:
//   - nodes: []etree.Node slice containing the tree structure to write
//   - filePath: string path where to write the JSON file
//
// Returns:
//   - error: any error encountered during JSON conversion, marshaling or file writing
//
// Example:
//   nodes := []etree.Node{
//     {
//       Key: "config",
//       Type: etree.NodeTypeObject,
//       Children: []etree.Node{
//         {Key: "setting", Type: etree.NodeTypeString, Value: "value"},
//       },
//     },
//   }
//   err := writeJSONFile(nodes, "config.json")
func writeJSONFile(nodes []etree.Node, filePath string) error {
    data := convertNodesToJSON(nodes)
    if data == nil {
        return fmt.Errorf("invalid node structure")
    }
    
    jsonData, err := json.MarshalIndent(data, "", "    ")
    if err != nil {
        return fmt.Errorf("error marshaling JSON: %v", err)
    }

    return os.WriteFile(filePath, jsonData, 0644)
}