package handler

import (
	"context"
	"errors"
	"io/fs"
	"strings"

	"detector/api"
	"detector/internal/usbfs"
	"detector/internal/usbfs/mtp"
)

const transferDisabled = "file transfer is disabled (transfer.enabled = false)"

func toAPILocation(l usbfs.Location) api.UsbFileLocation {
	out := api.UsbFileLocation{Id: l.ID, Kind: api.UsbFileLocationKind(l.Kind), Name: l.Name, Detail: l.Detail,
		Size: l.Size, Free: l.Free, ReadOnly: l.ReadOnly}
	if l.Error != "" {
		out.Error = &l.Error
	}
	return out
}

// fileErrKind classifies service errors: 400 / 404 / 409 (0 = internal).
func fileErrKind(err error) int {
	switch {
	case errors.Is(err, usbfs.ErrBusy), errors.Is(err, mtp.ErrBusy):
		return 409
	case errors.Is(err, usbfs.ErrNotFound), errors.Is(err, mtp.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		return 404
	}
	// invalid paths, device problems (locked phone, libusb missing, MTP errors,
	// permissions): report the reason to the UI
	return 400
}

func (h *Handler) ListUsbFileLocations(ctx context.Context, _ api.ListUsbFileLocationsRequestObject) (api.ListUsbFileLocationsResponseObject, error) {
	if h.files == nil {
		return api.ListUsbFileLocations404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: transferDisabled}}, nil
	}
	locs, notes := h.files.Locations(ctx)
	out := api.ListUsbFileLocations200JSONResponse{Locations: []api.UsbFileLocation{}, Notes: nonNil(notes)}
	for _, l := range locs {
		out.Locations = append(out.Locations, toAPILocation(l))
	}
	return out, nil
}

func (h *Handler) ListUsbFiles(ctx context.Context, req api.ListUsbFilesRequestObject) (api.ListUsbFilesResponseObject, error) {
	if h.files == nil {
		return api.ListUsbFiles404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: transferDisabled}}, nil
	}
	dir := ""
	if req.Params.Dir != nil {
		dir = *req.Params.Dir
	}
	var exts []string
	if req.Params.Ext != nil && *req.Params.Ext != "" {
		exts = strings.Split(*req.Params.Ext, ",")
	}
	l, err := h.files.List(ctx, req.Params.Location, dir, exts)
	if err != nil {
		msg := api.Error{Message: err.Error()}
		switch fileErrKind(err) {
		case 409:
			return api.ListUsbFiles409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(msg)}, nil
		case 404:
			return api.ListUsbFiles404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(msg)}, nil
		}
		return api.ListUsbFiles400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(msg)}, nil
	}
	out := api.ListUsbFiles200JSONResponse{Location: toAPILocation(l.Location), Dir: l.Dir, Entries: []api.UsbFileEntry{}}
	for _, e := range l.Entries {
		ae := api.UsbFileEntry{Id: e.ID, Name: e.Name, Dir: e.Dir, Size: e.Size}
		if !e.Modified.IsZero() {
			t := e.Modified.In(h.loc)
			ae.Modified = &t
		}
		out.Entries = append(out.Entries, ae)
	}
	return out, nil
}

func (h *Handler) toAPIJob(j usbfs.Job) api.UsbTransferJob {
	out := api.UsbTransferJob{Id: j.ID, From: j.From, To: j.To, FromName: j.FromName, ToName: j.ToName, Move: j.Move,
		State: api.UsbTransferJobState(j.State), Files: j.Files, Folders: j.Folders, Done: j.Done, Failed: j.Failed, Skipped: j.Skipped,
		Bytes: j.Bytes, BytesDone: j.BytesDone, Current: j.Current, StartedAt: j.StartedAt.In(h.loc),
		Results: []api.UsbTransferFile{}}
	if !j.FinishedAt.IsZero() {
		t := j.FinishedAt.In(h.loc)
		out.FinishedAt = &t
	}
	for _, r := range j.Results {
		f := api.UsbTransferFile{Name: r.Name, Ok: r.OK}
		if r.Error != "" {
			f.Error = &r.Error
		}
		out.Results = append(out.Results, f)
	}
	return out
}

func (h *Handler) ListUsbTransfers(_ context.Context, _ api.ListUsbTransfersRequestObject) (api.ListUsbTransfersResponseObject, error) {
	if h.files == nil {
		return api.ListUsbTransfers404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: transferDisabled}}, nil
	}
	out := api.ListUsbTransfers200JSONResponse{Items: []api.UsbTransferJob{}}
	for _, j := range h.files.Jobs() {
		out.Items = append(out.Items, h.toAPIJob(j))
	}
	return out, nil
}

func (h *Handler) StartUsbTransfer(ctx context.Context, req api.StartUsbTransferRequestObject) (api.StartUsbTransferResponseObject, error) {
	if h.files == nil {
		return api.StartUsbTransfer404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: transferDisabled}}, nil
	}
	b := req.Body
	if b == nil {
		return api.StartUsbTransfer400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{Message: "body required"}}, nil
	}
	r := usbfs.Request{From: b.From, Items: b.Items, To: b.To}
	if b.FromDir != nil {
		r.FromDir = *b.FromDir
	}
	if b.ToDir != nil {
		r.ToDir = *b.ToDir
	}
	r.Move = b.Move != nil && *b.Move
	r.Overwrite = b.Overwrite != nil && *b.Overwrite
	if b.Ext != nil && *b.Ext != "" {
		r.Ext = strings.Split(*b.Ext, ",")
	}
	j, err := h.files.Start(ctx, r)
	if err != nil {
		msg := api.Error{Message: err.Error()}
		switch fileErrKind(err) {
		case 409:
			return api.StartUsbTransfer409JSONResponse{ConflictJSONResponse: api.ConflictJSONResponse(msg)}, nil
		case 404:
			return api.StartUsbTransfer404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(msg)}, nil
		}
		return api.StartUsbTransfer400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(msg)}, nil
	}
	return api.StartUsbTransfer202JSONResponse(h.toAPIJob(j)), nil
}

func (h *Handler) CancelUsbTransfer(_ context.Context, req api.CancelUsbTransferRequestObject) (api.CancelUsbTransferResponseObject, error) {
	if h.files == nil {
		return api.CancelUsbTransfer404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: transferDisabled}}, nil
	}
	if err := h.files.Cancel(req.Id); err != nil {
		return api.CancelUsbTransfer404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: err.Error()}}, nil
	}
	return api.CancelUsbTransfer204Response{}, nil
}
