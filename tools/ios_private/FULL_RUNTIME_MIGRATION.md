# Full runtime: tek yetkili durumla aşamalı geçiş

Talha'nın tam dispatcher, 23.278 fonksiyonluk corpus, COM/D3D9 → Metal,
shader çeviricisi ve oyun özelindeki override/optimizasyonları ana oyun yoludur.
Doğrulanmış yeni bileşenler korunur ve somut adaptörlerle bu yola taşınır.
Aynı oyun sürecinde ikinci heap/TLS/handle/critical/process durumu kurulmaz.
Bounded startup parity ayrı test sürecidir; oyun oturumuna GuestWindows eklenmez.

| Alt sistem | Mevcut uygulamalar ve kaynak kanıtı | Oyun oturumunda seçilen tek yetkili uygulama | Adaptör / sıradaki doğrulama |
| --- | --- | --- | --- |
| Bellek | `mem.c` zaten `guest_memory.c` üzerinden reserve/commit yapıyor; aynı `g_mem` ve bitmap | Ortak `guest_memory.c` | Legacy `mem_*` ABI'si aynı VM'ye gider; 16 KiB sayfa, sınırlar ve izin testleri korunur. İkinci VM yok. |
| PE | Legacy `mem_load_pe` ham section kopyası; `guest_pe_load` format/sınır/çakışma/entry doğruluyor ve header/BSS'yi haritalıyor | Checked `guest_pe_load` için legacy adaptör uygulandı (native test bekliyor) | `mem_load_pe` tek yükleyiciye delege eder, image/resource globals'ını sonuçtan yayınlar. Önce sentetik PE adapter testleri; sonra exact private EXE ve ilk boot. |
| CPU / EFLAGS / bootstrap | İki yol aynı `CPU`/`cpu.h` ve `guest_bootstrap_init` kullanıyor | Ortak CPU ve bootstrap | EFLAGS.ID ve aritmetik düzeltmeleri korunur; eski adres-bağımlı workaround geri gelmez. Diagnostic oracle ayrı kalır. |
| Dispatch | `dispatch.c` COM/import/override/genexec yönlendiriyor; statik tablo `GuestDispatch` | Tam `dispatch.c` + ortak `guest_dispatch.c` tablosu | 128 shard/fntab, gerçek giriş ve güçlü backend sembolleri linker map ile doğrulanır. Bounded executor transfer ABI'si karıştırılmaz. |
| Heap | Legacy galloc alanı `0x10000000..0x2f000000`; checked `GuestHeapSet` dört 64 MiB arena / heap başına 256 descriptor sınırı taşıyor | İlk boot için legacy tek allocator | Arena aralıkları çakışıyor: GuestHeapSet paralel açılmaz. Önce gerçek tahsis boyutu/zirve/count envanteri; ardından checked allocator'ın kapasite ve legacy `win32_alloc` adaptörü test edilerek tek seferde geçiş. Kaynak ve heap/realloc testleri korunur. |
| TLS | Legacy `Tls*` TEB+0x2c static vector veya process-global fallback kullanıyor; checked TLS dynamic slotları TEB+0xe10'da tutuyor, 64 key/thread sınırı ve detach var | İlk compile/boot bazında mevcut legacy TLS; checked TLS geçiş adayı | Static PE TLS ile dynamic TLS ayrımı doğrulanacak. Tüm `Tls*` çağrıları ve gerçek CreateThread/timer detach aynı GuestTLSSet'e geçirilecek; iki tablo aynı oturumda tutulmayacak. Önce thread isolation/free/reuse regresyonları. |
| Critical section | Legacy 512 recursive mutex ve GIL release/wait; checked modül 64 object ve nonblocking EBUSY sözleşmesi | İlk boot için legacy mutex tablosu | Checked preflight/ownership doğruluğu alınırken GIL bırakma ve bloklama korunmalı. Aynı guest adresi iki mutex tablosuna kaydolmayacak. Contention/recursion/delete testleri geçmeden değişim yok. |
| Win32 / process / handles | Legacy import bridge COM/file/thread ile bütün; checked GuestWindows sınırlı ve farklı typed state tutuyor | Tek legacy import bridge ve alt sistem sahipleri | Genel ikinci GuestWindows kurulmaz. Doğrulanmış saf handler'lar veya alt sistem adaptörleri API bazında taşınır; heap/TLS/handle sahibi bypass edilmez. Unsupported/fallback davranışı gözlemlenir; diagnostic başarı yüzdesi oyun ilerlemesi sayılmaz. |
| Cursor/input | Ortak `guest_cursor` snapshot; legacy Metal fare adaptörleri aynı isimlere sahipti | Tek ortak snapshot + gerçek Metal adapter | Full hedef duplicate adapters'ı `NFSU2_LEGACY_METAL_INPUT` ile kapatır. UIKit/GC keyboard güçlü InputBridge'de; mouse/absolute cursor gerçek backend'de aynı snapshot'tan okunur. |
| Dosyalar / kayıt | `fileio.c` case-insensitive game root + save overlay; checked `guest_file` ayrı handle tablosu | İlk boot için `fileio.c` | Folder import sandbox kopyası, save root Application Support/NFSU2/Saves. İkinci file handle tablosu yok. Registry hâlen aynı app container HOME altında ayrı `.nfsu2_registry`; bunu ikinci registry durumuna dönüştürmeden tek köke adapte et. |
| Renderer / ses | Talha `metal.m`/`vsemu.c`/`com.c`; iOS uyarlamalı `audio.m` | Aynı gerçek backend'ler | UIKit CAMetalLayer ve worker; gerçek D3D draw/shader/present gözlemi ve cihaz görüntüsü/sesi ayrı kabul ölçütüdür. Weak readiness full hedefe girmez. |

Uygulama sırası: (1) tüm shard'ların gerçek ARM64 compile/link sonucu;
(2) checked PE adaptörü ve tek oturumun iPad boot'u; (3) gerçek oyun karesi;
(4) menü ve kontrol edilebilir yarış. Heap/TLS/critical geçişleri bu ana hedefe
hizmet eden sınırlı adımlardır; yeni startup frontier kovalamak ana iş değildir.

İlk kaynak adayı: `85a9c8d6c0c7ec8e05089297f78b936645c9582e`.
Yerel exact üretim: 128 shard, 23.278 kayıt (4 fallback), 252 import,
35 override; `gen/all/ios-full-manifest.json` clean source pin ve 132 dosya hash'i
kaydediyor. Bu üretim ve kaynak incelemesi oyun boot/render kanıtı değildir.

Checked PE adaptörü sonraki kaynak değişikliğinde uygulanmıştır: tam runtime için
`mem_load_pe` yalnız `guest_pe_load` çağırır; ikinci haritalama/durum yoktur.
Sentetik malformed/valid/BSS/EBUSY testleri eklendi; özel CI exact EXE metadata
kontrolünü de yapar. Native sonuç alınmadan bu adım doğrulanmış sayılmaz.
