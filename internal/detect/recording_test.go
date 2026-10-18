package detect

import "testing"

func TestMatchRecTools(t *testing.T) {
	procs := []proc{
		{PID: 1, Exe: "/opt/homebrew/bin/ffmpeg", Args: "ffmpeg -f avfoundation -i 1:0 out.mp4"},
		{PID: 2, Exe: "/opt/homebrew/bin/ffmpeg", Args: "ffmpeg -i in.mov out.mp4"}, // transcode only
		{PID: 3, Exe: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk"},
		{PID: 4, Exe: "/Applications/AnyDesk.app/Contents/MacOS/AnyDesk"}, // helper of the same app
		{PID: 5, Exe: "/usr/sbin/screencapture", Args: "screencapture -x shot.png"},
		{PID: 6, Exe: "/usr/sbin/screencapture", Args: "screencapture -v rec.mov"},
		{PID: 7, Exe: "/usr/bin/arecord", Args: "arecord -f cd out.wav"},
	}
	got := map[string]int{}
	for _, tl := range matchRecTools(procs) {
		got[tl.Kind+"|"+tl.Label] = tl.PID
	}
	want := map[string]int{
		RecScreen + "|ffmpeg 화면 캡처":      1,
		RecRemote + "|AnyDesk":           3,
		RecScreen + "|screencapture 동영상": 6,
		RecMic + "|arecord":              7,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, pid := range want {
		if got[k] != pid {
			t.Errorf("%s: pid %d, want %d (all: %v)", k, got[k], pid, got)
		}
	}
}
