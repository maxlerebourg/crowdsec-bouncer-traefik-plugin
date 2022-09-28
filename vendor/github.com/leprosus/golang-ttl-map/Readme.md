# Golang in-memory key-value storage with time-to-life

## Create new map

```go
import ttl_map "github.com/leprosus/golang-ttl-map"

heap := ttl_map.New()
heap.Path("/path/to/auto-save-file.tsv")
```

## Set/Get

```go
heap.Set("key", "value", 60)

value := heap.Get("key")
```

## Save/Restore

```go
heap.Save()

heap.Restore()
```

## Save/Restore complex data structure

```go
var m = map[string]string{}
m["key"] = "value"

heap.Set("obj", m, 60)

heap.Support(map[string]string)

heap.Save()

heap.Restore()
```

## List all methods

* New() - creates new map
* Path(filePath) - sets file path to save/autosave/restore
* Set(key, value, ttl) - adds value by key with ttl in seconds
* Get(key) - returns value or empty string
* Del(key) - deletes value by key
* Range(fn func(key string, value string, ttl int64)) - iterates all actual data
* Support(struct) - registers new structure support (the method is important in a case with complex structure or map)
* Save() - saves map in tsv file
* Restore() - restores map from tsv file