// genres 生成 Windows 版的图标与 exe 资源（图标、清单、版本信息）。
// 图标是自己画的盾牌：macOS 版用的 SF Symbols 只允许在苹果平台使用，不能搬过来。
//
//	go run ./tools/genres -version 1.0.0 -out cmd
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
	"golang.org/x/image/vector"
)

var (
	deep    = color.NRGBA{0x06, 0x3d, 0x4a, 0xff}
	bright  = color.NRGBA{0x12, 0x9e, 0x86, 0xff}
	shieldC = color.NRGBA{0xff, 0xff, 0xff, 0xff}
	checkC  = color.NRGBA{0x0e, 0x7a, 0x64, 0xff}
)

func lerp(a, b color.NRGBA, t float64) color.NRGBA {
	f := func(x, y uint8) uint8 { return uint8(math.Round(float64(x) + (float64(y)-float64(x))*t)) }
	return color.NRGBA{f(a.R, b.R), f(a.G, b.G), f(a.B, b.B), 0xff}
}

// roundedRect 往光栅器里加一个圆角矩形（四段三次贝塞尔近似圆角）
func roundedRect(z *vector.Rasterizer, x0, y0, x1, y1, r float32) {
	const k = 0.5523
	z.MoveTo(x0+r, y0)
	z.LineTo(x1-r, y0)
	z.CubeTo(x1-r+r*k, y0, x1, y0+r-r*k, x1, y0+r)
	z.LineTo(x1, y1-r)
	z.CubeTo(x1, y1-r+r*k, x1-r+r*k, y1, x1-r, y1)
	z.LineTo(x0+r, y1)
	z.CubeTo(x0+r-r*k, y1, x0, y1-r+r*k, x0, y1-r)
	z.LineTo(x0, y0+r)
	z.CubeTo(x0, y0+r-r*k, x0+r-r*k, y0, x0+r, y0)
	z.ClosePath()
}

// shield 盾牌外形：上缘平直略带肩，下部收成尖
func shield(z *vector.Rasterizer, cx, top, w, h float32) {
	l, r := cx-w/2, cx+w/2
	z.MoveTo(cx, top)
	z.CubeTo(cx+w*0.18, top+h*0.08, r-w*0.08, top+h*0.10, r, top+h*0.12)
	z.LineTo(r, top+h*0.45)
	z.CubeTo(r, top+h*0.72, cx+w*0.22, top+h*0.90, cx, top+h)
	z.CubeTo(cx-w*0.22, top+h*0.90, l, top+h*0.72, l, top+h*0.45)
	z.LineTo(l, top+h*0.12)
	z.CubeTo(l+w*0.08, top+h*0.10, cx-w*0.18, top+h*0.08, cx, top)
	z.ClosePath()
}

// stroke 把折线描成有宽度的多边形（只用于对勾，两段，端点不需要圆头）
func stroke(z *vector.Rasterizer, pts [][2]float32, width float32) {
	for i := 0; i+1 < len(pts); i++ {
		a, b := pts[i], pts[i+1]
		dx, dy := b[0]-a[0], b[1]-a[1]
		n := float32(math.Hypot(float64(dx), float64(dy)))
		ox, oy := -dy/n*width/2, dx/n*width/2
		// 两端各延长半个线宽，让拐角处闭合
		ex, ey := dx/n*width/2, dy/n*width/2
		z.MoveTo(a[0]-ex+ox, a[1]-ey+oy)
		z.LineTo(b[0]+ex+ox, b[1]+ey+oy)
		z.LineTo(b[0]+ex-ox, b[1]+ey-oy)
		z.LineTo(a[0]-ex-ox, a[1]-ey-oy)
		z.ClosePath()
	}
}

func fill(dst *image.NRGBA, z *vector.Rasterizer, src image.Image) {
	z.Draw(dst, dst.Bounds(), src, image.Point{})
}

func render(px int) *image.NRGBA {
	s := float32(px)
	img := image.NewNRGBA(image.Rect(0, 0, px, px))

	// 底板：深青到防护绿的斜向渐变
	grad := image.NewNRGBA(img.Bounds())
	for y := 0; y < px; y++ {
		for x := 0; x < px; x++ {
			t := (float64(x)*0.35 + float64(px-y)*0.65) / float64(px)
			grad.SetNRGBA(x, y, lerp(deep, bright, t))
		}
	}
	z := vector.NewRasterizer(px, px)
	inset := s * 0.06
	roundedRect(z, inset, inset, s-inset, s-inset, s*0.22)
	fill(img, z, grad)

	z = vector.NewRasterizer(px, px)
	sw, sh, top := s*0.56, s*0.66, s*0.16
	shield(z, s/2, top, sw, sh)
	fill(img, z, image.NewUniform(shieldC))

	z = vector.NewRasterizer(px, px)
	cy := top + sh*0.46
	stroke(z, [][2]float32{{s/2 - sw*0.22, cy}, {s/2 - sw*0.05, cy + sh*0.15}, {s/2 + sw*0.24, cy - sh*0.15}}, sw*0.13)
	fill(img, z, image.NewUniform(checkC))
	return img
}

func pngBytes(img image.Image) []byte {
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		log.Fatal(err)
	}
	return b.Bytes()
}

func main() {
	ver := flag.String("version", "1.0.0", "版本号")
	out := flag.String("out", "cmd", "cmd 目录")
	flag.Parse()

	sizes := []int{16, 20, 24, 32, 40, 48, 64, 128, 256}
	var imgs []image.Image
	for _, s := range sizes {
		imgs = append(imgs, render(s))
	}
	appIcon, err := winres.NewIconFromImages(imgs)
	if err != nil {
		log.Fatal(err)
	}

	// 托盘用小尺寸的同款图标
	trayDir := filepath.Join(*out, "aiguard", "assets")
	must(os.MkdirAll(trayDir, 0o755))
	must(os.WriteFile(filepath.Join(trayDir, "app.png"), pngBytes(render(256)), 0o644))
	var trayImgs []image.Image
	for _, s := range []int{16, 20, 24, 32, 48} {
		trayImgs = append(trayImgs, render(s))
	}
	trayIcon, err := winres.NewIconFromImages(trayImgs)
	must(err)
	var trayBuf bytes.Buffer
	must(trayIcon.SaveICO(&trayBuf))
	must(os.WriteFile(filepath.Join(trayDir, "tray.ico"), trayBuf.Bytes(), 0o644))

	for _, target := range []struct {
		dir, name, desc string
		gui             bool
	}{
		{"aiguard", "AIGuard.exe", "AI 出差管家", true},
		{"aiguard-service", "aiguard-service.exe", "AI 出差管家防护服务", false},
	} {
		rs := winres.ResourceSet{}
		must(rs.SetIcon(winres.Name("APPICON"), appIcon))
		m := winres.AppManifest{
			Identity:            winres.AssemblyIdentity{Name: "AIGuard." + target.dir},
			Description:         target.desc,
			ExecutionLevel:      winres.AsInvoker,
			DPIAwareness:        winres.DPIPerMonitorV2,
			UseCommonControlsV6: true,
			LongPathAware:       true,
			Compatibility:       winres.Win10AndAbove,
		}
		if !target.gui {
			m.DPIAwareness = winres.DPIAware
		}
		rs.SetManifest(m)

		var vi version.Info
		vi.SetFileVersion(*ver)
		vi.SetProductVersion(*ver)
		for k, v := range map[string]string{
			"ProductName":      "AI 出差管家",
			"FileDescription":  target.desc,
			"OriginalFilename": target.name,
			"LegalCopyright":   "GPL-3.0",
			"CompanyName":      "AIGuard",
		} {
			must(vi.Set(0x0804, k, v))
		}
		rs.SetVersionInfo(vi)

		for _, arch := range []winres.Arch{winres.ArchAMD64, winres.ArchARM64} {
			path := filepath.Join(*out, target.dir, fmt.Sprintf("rsrc_windows_%s.syso", arch))
			f, err := os.Create(path)
			must(err)
			must(rs.WriteObject(f, arch))
			must(f.Close())
		}
	}
	fmt.Println("资源已生成")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
