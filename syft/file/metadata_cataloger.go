package file

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/source"
)

type MetadataCataloger struct {
}

func NewMetadataCataloger() *MetadataCataloger {
	return &MetadataCataloger{}
}

func (i *MetadataCataloger) Catalog(resolver source.FileResolver, coordinates ...source.Coordinates) (map[source.Coordinates]source.FileMetadata, error) {
	results := make(map[source.Coordinates]source.FileMetadata)
	var locations <-chan source.Location

	if len(coordinates) == 0 {
		locations = resolver.AllLocations()
	} else {
		locations = func() <-chan source.Location {
			ch := make(chan source.Location)
			go func() {
				close(ch)
				for _, c := range coordinates {
					ch <- source.NewLocationFromCoordinates(c)
				}
			}()
			return ch
		}()
	}

	stage, prog := metadataCatalogingProgress(int64(len(locations)))
	for location := range locations {
		stage.Current = location.RealPath
		metadata, err := resolver.FileMetadataByLocation(location)
		if err != nil {
			return nil, err
		}

		results[location.Coordinates] = metadata
		prog.N++
	}
	log.Debugf("file metadata cataloger processed %d files", prog.N)
	prog.SetCompleted()
	return results, nil
}

func metadataCatalogingProgress(locations int64) (*progress.Stage, *progress.Manual) {
	stage := &progress.Stage{}
	prog := &progress.Manual{
		Total: locations,
	}

	bus.Publish(partybus.Event{
		Type: event.FileMetadataCatalogerStarted,
		Value: struct {
			progress.Stager
			progress.Progressable
		}{
			Stager:       progress.Stager(stage),
			Progressable: prog,
		},
	})

	return stage, prog
}
