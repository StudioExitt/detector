package handler

import (
	"context"
	"errors"
	"regexp"

	"detector/api"
	"detector/internal/detect"
)

// disk4 / sdb / nvme1n1 / mmcblk0, or a USB device id from the status API
var reUsbTarget = regexp.MustCompile(`^(disk\d+|[a-z]+\d*[a-z0-9]*|usb-[0-9A-Za-z.\-]+)$`)

func (h *Handler) GetUsbStatus(_ context.Context, _ api.GetUsbStatusRequestObject) (api.GetUsbStatusResponseObject, error) {
	v, _ := h.detect.Snapshot("usb")
	s, ok := v.(detect.UsbSnapshot)
	if !ok {
		return api.GetUsbStatus404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{
			Message: "USB status not available yet (detect.usb disabled or first run pending)"}}, nil
	}
	out := api.GetUsbStatus200JSONResponse{At: s.At.In(h.loc), Platform: s.Platform, Root: s.Root, Notes: nonNil(s.Notes),
		Devices: []api.UsbDevice{}, Disks: []api.UsbDisk{}, Recent: []api.UsbActivity{}}
	for _, d := range s.Devices {
		out.Devices = append(out.Devices, api.UsbDevice{Id: d.ID, Name: d.Name, Vendor: d.Vendor, Serial: d.Serial,
			VendorId: d.VendorID, ProductId: d.ProductID, Speed: d.Speed, Kinds: nonNil(d.Kinds), Disks: nonNil(d.Disks),
			Clients: usbProcs(d.Clients), Trusted: d.Trusted, Known: d.Known, Since: d.Since.In(h.loc)})
	}
	for _, k := range s.Disks {
		ak := api.UsbDisk{Disk: k.Disk, DeviceId: k.DeviceID, Name: k.Name, Bus: k.Bus, Size: int64(k.Size), Removable: k.Removable,
			Volumes: []api.UsbVolume{}, Occupants: usbProcs(k.Occupants), ReadBytes: int64(k.ReadBytes), WriteBytes: int64(k.WriteBytes),
			WriteBps: k.WriteBps, Write10m: int64(k.Write10m), StatsKnown: k.StatsKnown, Trusted: k.Trusted}
		for _, v := range k.Volumes {
			ak.Volumes = append(ak.Volumes, api.UsbVolume{Id: v.ID, Name: v.Name, MountPoint: v.MountPoint, Fs: v.FS,
				Size: int64(v.Size), Free: int64(v.Free), ReadOnly: v.ReadOnly})
		}
		out.Disks = append(out.Disks, ak)
	}
	for _, r := range s.Recent {
		out.Recent = append(out.Recent, api.UsbActivity{At: r.At.In(h.loc), Kind: r.Kind, Target: r.Target, Detail: r.Detail, Ok: r.OK})
	}
	return out, nil
}

func usbProcs(ps []detect.UsbProc) []api.UsbProc {
	out := make([]api.UsbProc, 0, len(ps))
	for _, p := range ps {
		out = append(out, api.UsbProc{Pid: p.PID, Name: p.Name, User: p.User, Exe: p.Exe, Files: nonNil(p.Files), Count: p.Count, System: p.System})
	}
	return out
}

func usbResult(r detect.UsbActionResult) api.UsbActionResult {
	out := api.UsbActionResult{Ok: r.OK, Steps: []api.UsbStep{}}
	for _, s := range r.Steps {
		out.Steps = append(out.Steps, api.UsbStep{Action: s.Action, Target: s.Target, Ok: s.OK, Detail: s.Detail})
	}
	return out
}

func (h *Handler) ReleaseUsb(ctx context.Context, req api.ReleaseUsbRequestObject) (api.ReleaseUsbResponseObject, error) {
	b := req.Body
	if b == nil || !reUsbTarget.MatchString(b.Target) {
		return api.ReleaseUsb400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{Message: "invalid target"}}, nil
	}
	hard := false
	if b.Signal != nil {
		if !b.Signal.Valid() {
			return api.ReleaseUsb400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{Message: "signal must be term or kill"}}, nil
		}
		hard = *b.Signal == api.Kill
	}
	var pids []int
	if b.Pids != nil {
		pids = *b.Pids
	}
	res, err := h.detect.UsbRelease(ctx, b.Target, pids, hard, b.Eject != nil && *b.Eject)
	if errors.Is(err, detect.ErrUsbTarget) || errors.Is(err, detect.ErrUnavailable) {
		return api.ReleaseUsb404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: err.Error()}}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.ReleaseUsb200JSONResponse(usbResult(res)), nil
}

func (h *Handler) EjectUsb(ctx context.Context, req api.EjectUsbRequestObject) (api.EjectUsbResponseObject, error) {
	b := req.Body
	if b == nil || !reUsbTarget.MatchString(b.Disk) {
		return api.EjectUsb400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse{Message: "invalid disk"}}, nil
	}
	res, err := h.detect.UsbEject(ctx, b.Disk, b.Force != nil && *b.Force)
	if errors.Is(err, detect.ErrUsbTarget) || errors.Is(err, detect.ErrUnavailable) {
		return api.EjectUsb404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse{Message: err.Error()}}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.EjectUsb200JSONResponse(usbResult(res)), nil
}
