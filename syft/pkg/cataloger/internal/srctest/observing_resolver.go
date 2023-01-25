package srctest

import (
	"fmt"
	"io"
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/source"
)

var _ source.FileResolver = (*ObservingResolver)(nil)

type ObservingResolver struct {
	decorated          source.FileResolver
	pathQueries        map[string][]string
	pathResponses      []source.Location
	contentQueries     []source.Location
	emptyPathResponses map[string][]string
}

func NewObservingResolver(resolver source.FileResolver) *ObservingResolver {
	return &ObservingResolver{
		decorated:          resolver,
		pathResponses:      make([]source.Location, 0),
		emptyPathResponses: make(map[string][]string),
		pathQueries:        make(map[string][]string),
	}
}

// testing helpers...

func (r *ObservingResolver) ObservedPathQuery(input string) bool {
	for _, vs := range r.pathQueries {
		for _, v := range vs {
			if v == input {
				return true
			}
		}
	}
	return false
}

func (r *ObservingResolver) ObservedPathResponses(path string) bool {
	for _, loc := range r.pathResponses {
		if loc.RealPath == path {
			return true
		}
	}
	return false
}

func (r *ObservingResolver) ObservedContentQueries(path string) bool {
	for _, loc := range r.contentQueries {
		if loc.RealPath == path {
			return true
		}
	}
	return false
}

func (r *ObservingResolver) AllContentQueries() []string {
	observed := strset.New()
	for _, loc := range r.contentQueries {
		observed.Add(loc.RealPath)
	}
	return observed.List()
}

func (r *ObservingResolver) AllPathQueries() map[string][]string {
	return r.pathQueries
}

func (r *ObservingResolver) PruneUnfulfilledPathResponses(ignore map[string][]string, ignorePaths ...string) {
	if ignore == nil {
		return
	}
	// remove any paths that were ignored for specific calls
	for k, v := range ignore {
		results := r.emptyPathResponses[k]
		for _, ig := range v {
			for i, result := range results {
				if result == ig {
					results = append(results[:i], results[i+1:]...)
					break
				}
			}
		}
		if len(results) > 0 {
			r.emptyPathResponses[k] = results
		} else {
			delete(r.emptyPathResponses, k)
		}
	}

	// remove any paths that were ignored for all calls
	for _, ig := range ignorePaths {
		for k, v := range r.emptyPathResponses {
			for i, result := range v {
				if result == ig {
					v = append(v[:i], v[i+1:]...)
					break
				}
			}
			if len(v) > 0 {
				r.emptyPathResponses[k] = v
			} else {
				delete(r.emptyPathResponses, k)
			}
		}
	}
}

func (r *ObservingResolver) HasUnfulfilledPathRequests() bool {
	return len(r.emptyPathResponses) > 0
}

func (r *ObservingResolver) PrettyUnfulfilledPathRequests() string {
	var res string
	var keys []string

	for k := range r.emptyPathResponses {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		res += fmt.Sprintf("   %s: %+v\n", k, r.emptyPathResponses[k])
	}
	return res
}

// For the file path resolver...

func (r *ObservingResolver) addPathQuery(name string, input ...string) {
	r.pathQueries[name] = append(r.pathQueries[name], input...)
}

func (r *ObservingResolver) addPathResponse(locs ...source.Location) {
	r.pathResponses = append(r.pathResponses, locs...)
}

func (r *ObservingResolver) addEmptyPathResponse(name string, locs []source.Location, paths ...string) {
	if len(locs) == 0 {
		results := r.emptyPathResponses[name]
		results = append(results, paths...)
		r.emptyPathResponses[name] = results
	}
}

func (r *ObservingResolver) FilesByPath(paths ...string) ([]source.Location, error) {
	name := "FilesByPath"
	r.addPathQuery(name, paths...)

	locs, err := r.decorated.FilesByPath(paths...)

	r.addPathResponse(locs...)
	r.addEmptyPathResponse(name, locs, paths...)
	return locs, err
}

func (r *ObservingResolver) FilesByGlob(patterns ...string) ([]source.Location, error) {
	name := "FilesByGlob"
	r.addPathQuery(name, patterns...)

	locs, err := r.decorated.FilesByGlob(patterns...)

	r.addPathResponse(locs...)
	r.addEmptyPathResponse(name, locs, patterns...)
	return locs, err
}

func (r *ObservingResolver) FilesByExtension(extensions ...string) ([]source.Location, error) {
	name := "FilesByExtension"
	r.addPathQuery(name, extensions...)

	locs, err := r.decorated.FilesByExtension(extensions...)

	r.addPathResponse(locs...)
	r.addEmptyPathResponse(name, locs, extensions...)
	return locs, err
}

func (r *ObservingResolver) FilesByBasename(filenames ...string) ([]source.Location, error) {
	name := "FilesByBasename"
	r.addPathQuery(name, filenames...)

	locs, err := r.decorated.FilesByBasename(filenames...)

	r.addPathResponse(locs...)
	r.addEmptyPathResponse(name, locs, filenames...)
	return locs, err
}

func (r *ObservingResolver) FilesByBasenameGlob(globs ...string) ([]source.Location, error) {
	name := "FilesByBasenameGlob"
	r.addPathQuery(name, globs...)

	locs, err := r.decorated.FilesByBasenameGlob(globs...)

	r.addPathResponse(locs...)
	r.addEmptyPathResponse(name, locs, globs...)
	return locs, err
}

func (r *ObservingResolver) FilesByMIMEType(types ...string) ([]source.Location, error) {
	name := "FilesByMIMEType"
	r.addPathQuery(name, types...)

	locs, err := r.decorated.FilesByMIMEType(types...)

	r.addPathResponse(locs...)
	r.addEmptyPathResponse(name, locs, types...)
	return locs, err
}

func (r *ObservingResolver) RelativeFileByPath(l source.Location, path string) *source.Location {
	name := "RelativeFileByPath"
	r.addPathQuery(name, path)

	loc := r.decorated.RelativeFileByPath(l, path)

	if loc != nil {
		r.addPathResponse(*loc)
	} else {
		results := r.emptyPathResponses[name]
		results = append(results, path)
		r.emptyPathResponses[name] = results
	}
	return loc
}

// For the content resolver methods...

func (r *ObservingResolver) FileContentsByLocation(location source.Location) (io.ReadCloser, error) {
	r.contentQueries = append(r.contentQueries, location)
	reader, err := r.decorated.FileContentsByLocation(location)
	return reader, err
}

// For the remaining resolver methods...

func (r *ObservingResolver) AllLocations() <-chan source.Location {
	return r.decorated.AllLocations()
}

func (r *ObservingResolver) HasPath(s string) bool {
	return r.decorated.HasPath(s)
}

func (r *ObservingResolver) FileMetadataByLocation(location source.Location) (source.FileMetadata, error) {
	return r.decorated.FileMetadataByLocation(location)
}
