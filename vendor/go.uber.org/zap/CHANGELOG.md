***REMOVED*** Changelog
All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

***REMOVED******REMOVED*** 1.27.0 (20 Feb 2024)
Enhancements:
* [***REMOVED***1378][]: Add `WithLazy` method for `SugaredLogger`.
* [***REMOVED***1399][]: zaptest: Add `NewTestingWriter` for customizing TestingWriter with more flexibility than `NewLogger`.
* [***REMOVED***1406][]: Add `Log`, `Logw`, `Logln` methods for `SugaredLogger`.
* [***REMOVED***1416][]: Add `WithPanicHook` option for testing panic logs.

Thanks to @defval, @dimmo, @arxeiss, and @MKrupauskas for their contributions to this release.

[***REMOVED***1378]: https://github.com/uber-go/zap/pull/1378
[***REMOVED***1399]: https://github.com/uber-go/zap/pull/1399
[***REMOVED***1406]: https://github.com/uber-go/zap/pull/1406
[***REMOVED***1416]: https://github.com/uber-go/zap/pull/1416

***REMOVED******REMOVED*** 1.26.0 (14 Sep 2023)
Enhancements:
* [***REMOVED***1297][]: Add Dict as a Field.
* [***REMOVED***1319][]: Add `WithLazy` method to `Logger` which lazily evaluates the structured
context.
* [***REMOVED***1350][]: String encoding is much (~50%) faster now.

Thanks to @hhk7734, @jquirke, and @cdvr1993 for their contributions to this release.

[***REMOVED***1297]: https://github.com/uber-go/zap/pull/1297
[***REMOVED***1319]: https://github.com/uber-go/zap/pull/1319
[***REMOVED***1350]: https://github.com/uber-go/zap/pull/1350

***REMOVED******REMOVED*** 1.25.0 (1 Aug 2023)

This release contains several improvements including performance, API additions,
and two new experimental packages whose APIs are unstable and may change in the
future.

Enhancements:
* [***REMOVED***1246][]: Add `zap/exp/zapslog` package for integration with slog.
* [***REMOVED***1273][]: Add `Name` to `Logger` which returns the Logger's name if one is set.
* [***REMOVED***1281][]: Add `zap/exp/expfield` package which contains helper methods
`Str` and `Strs` for constructing String-like zap.Fields.
* [***REMOVED***1310][]: Reduce stack size on `Any`.

Thanks to @knight42, @dzakaammar, @bcspragu, and @rexywork for their contributions
to this release.

[***REMOVED***1246]: https://github.com/uber-go/zap/pull/1246
[***REMOVED***1273]: https://github.com/uber-go/zap/pull/1273
[***REMOVED***1281]: https://github.com/uber-go/zap/pull/1281
[***REMOVED***1310]: https://github.com/uber-go/zap/pull/1310

***REMOVED******REMOVED*** 1.24.0 (30 Nov 2022)

Enhancements:
* [***REMOVED***1148][]: Add `Level` to both `Logger` and `SugaredLogger` that reports the
  current minimum enabled log level.
* [***REMOVED***1185][]: `SugaredLogger` turns errors to zap.Error automatically.

Thanks to @Abirdcfly, @craigpastro, @nnnkkk7, and @sashamelentyev for their
contributions to this release.

[***REMOVED***1148]: https://github.coml/uber-go/zap/pull/1148
[***REMOVED***1185]: https://github.coml/uber-go/zap/pull/1185

***REMOVED******REMOVED*** 1.23.0 (24 Aug 2022)

Enhancements:
* [***REMOVED***1147][]: Add a `zapcore.LevelOf` function to determine the level of a
  `LevelEnabler` or `Core`.
* [***REMOVED***1155][]: Add `zap.Stringers` field constructor to log arrays of objects
  that implement `String() string`.

[***REMOVED***1147]: https://github.com/uber-go/zap/pull/1147
[***REMOVED***1155]: https://github.com/uber-go/zap/pull/1155

***REMOVED******REMOVED*** 1.22.0 (8 Aug 2022)

Enhancements:
* [***REMOVED***1071][]: Add `zap.Objects` and `zap.ObjectValues` field constructors to log
  arrays of objects. With these two constructors, you don't need to implement
  `zapcore.ArrayMarshaler` for use with `zap.Array` if those objects implement
  `zapcore.ObjectMarshaler`.
* [***REMOVED***1079][]: Add `SugaredLogger.WithOptions` to build a copy of an existing
  `SugaredLogger` with the provided options applied.
* [***REMOVED***1080][]: Add `*ln` variants to `SugaredLogger` for each log level.
  These functions provide a string joining behavior similar to `fmt.Println`.
* [***REMOVED***1088][]: Add `zap.WithFatalHook` option to control the behavior of the
  logger for `Fatal`-level log entries. This defaults to exiting the program.
* [***REMOVED***1108][]: Add a `zap.Must` function that you can use with `NewProduction` or
  `NewDevelopment` to panic if the system was unable to build the logger.
* [***REMOVED***1118][]: Add a `Logger.Log` method that allows specifying the log level for
  a statement dynamically.

Thanks to @cardil, @craigpastro, @sashamelentyev, @shota3506, and @zhupeijun
for their contributions to this release.

[***REMOVED***1071]: https://github.com/uber-go/zap/pull/1071
[***REMOVED***1079]: https://github.com/uber-go/zap/pull/1079
[***REMOVED***1080]: https://github.com/uber-go/zap/pull/1080
[***REMOVED***1088]: https://github.com/uber-go/zap/pull/1088
[***REMOVED***1108]: https://github.com/uber-go/zap/pull/1108
[***REMOVED***1118]: https://github.com/uber-go/zap/pull/1118

***REMOVED******REMOVED*** 1.21.0 (7 Feb 2022)

Enhancements:
*  [***REMOVED***1047][]: Add `zapcore.ParseLevel` to parse a `Level` from a string.
*  [***REMOVED***1048][]: Add `zap.ParseAtomicLevel` to parse an `AtomicLevel` from a
   string.

Bugfixes:
* [***REMOVED***1058][]: Fix panic in JSON encoder when `EncodeLevel` is unset.

Other changes:
* [***REMOVED***1052][]: Improve encoding performance when the `AddCaller` and
  `AddStacktrace` options are used together.

[***REMOVED***1047]: https://github.com/uber-go/zap/pull/1047
[***REMOVED***1048]: https://github.com/uber-go/zap/pull/1048
[***REMOVED***1052]: https://github.com/uber-go/zap/pull/1052
[***REMOVED***1058]: https://github.com/uber-go/zap/pull/1058

Thanks to @aerosol and @Techassi for their contributions to this release.

***REMOVED******REMOVED*** 1.20.0 (4 Jan 2022)

Enhancements:
* [***REMOVED***989][]: Add `EncoderConfig.SkipLineEnding` flag to disable adding newline
  characters between log statements.
* [***REMOVED***1039][]: Add `EncoderConfig.NewReflectedEncoder` field to customize JSON
  encoding of reflected log fields.

Bugfixes:
* [***REMOVED***1011][]: Fix inaccurate precision when encoding complex64 as JSON.
* [***REMOVED***554][], [***REMOVED***1017][]: Close JSON namespaces opened in `MarshalLogObject`
  methods when the methods return.
* [***REMOVED***1033][]: Avoid panicking in Sampler core if `thereafter` is zero.

Other changes:
* [***REMOVED***1028][]: Drop support for Go < 1.15.

[***REMOVED***554]: https://github.com/uber-go/zap/pull/554
[***REMOVED***989]: https://github.com/uber-go/zap/pull/989
[***REMOVED***1011]: https://github.com/uber-go/zap/pull/1011
[***REMOVED***1017]: https://github.com/uber-go/zap/pull/1017
[***REMOVED***1028]: https://github.com/uber-go/zap/pull/1028
[***REMOVED***1033]: https://github.com/uber-go/zap/pull/1033
[***REMOVED***1039]: https://github.com/uber-go/zap/pull/1039

Thanks to @psrajat, @lruggieri, @sammyrnycreal for their contributions to this release.

***REMOVED******REMOVED*** 1.19.1 (8 Sep 2021)

Bugfixes:
* [***REMOVED***1001][]: JSON: Fix complex number encoding with negative imaginary part. Thanks to @hemantjadon.
* [***REMOVED***1003][]: JSON: Fix inaccurate precision when encoding float32.

[***REMOVED***1001]: https://github.com/uber-go/zap/pull/1001
[***REMOVED***1003]: https://github.com/uber-go/zap/pull/1003

***REMOVED******REMOVED*** 1.19.0 (9 Aug 2021)

Enhancements:
* [***REMOVED***975][]: Avoid panicking in Sampler core if the level is out of bounds.
* [***REMOVED***984][]: Reduce the size of BufferedWriteSyncer by aligning the fields
  better.

[***REMOVED***975]: https://github.com/uber-go/zap/pull/975
[***REMOVED***984]: https://github.com/uber-go/zap/pull/984

Thanks to @lancoLiu and @thockin for their contributions to this release.

***REMOVED******REMOVED*** 1.18.1 (28 Jun 2021)

Bugfixes:
* [***REMOVED***974][]: Fix nil dereference in logger constructed by `zap.NewNop`.

[***REMOVED***974]: https://github.com/uber-go/zap/pull/974

***REMOVED******REMOVED*** 1.18.0 (28 Jun 2021)

Enhancements:
* [***REMOVED***961][]: Add `zapcore.BufferedWriteSyncer`, a new `WriteSyncer` that buffers
  messages in-memory and flushes them periodically.
* [***REMOVED***971][]: Add `zapio.Writer` to use a Zap logger as an `io.Writer`.
* [***REMOVED***897][]: Add `zap.WithClock` option to control the source of time via the
  new `zapcore.Clock` interface.
* [***REMOVED***949][]: Avoid panicking in `zap.SugaredLogger` when arguments of `*w`
  methods don't match expectations.
* [***REMOVED***943][]: Add support for filtering by level or arbitrary matcher function to
  `zaptest/observer`.
* [***REMOVED***691][]: Comply with `io.StringWriter` and `io.ByteWriter` in Zap's
  `buffer.Buffer`.

Thanks to @atrn0, @ernado, @heyanfu, @hnlq715, @zchee
for their contributions to this release.

[***REMOVED***691]: https://github.com/uber-go/zap/pull/691
[***REMOVED***897]: https://github.com/uber-go/zap/pull/897
[***REMOVED***943]: https://github.com/uber-go/zap/pull/943
[***REMOVED***949]: https://github.com/uber-go/zap/pull/949
[***REMOVED***961]: https://github.com/uber-go/zap/pull/961
[***REMOVED***971]: https://github.com/uber-go/zap/pull/971

***REMOVED******REMOVED*** 1.17.0 (25 May 2021)

Bugfixes:
* [***REMOVED***867][]: Encode `<nil>` for nil `error` instead of a panic.
* [***REMOVED***931][], [***REMOVED***936][]: Update minimum version constraints to address
  vulnerabilities in dependencies.

Enhancements:
* [***REMOVED***865][]: Improve alignment of fields of the Logger struct, reducing its
  size from 96 to 80 bytes.
* [***REMOVED***881][]: Support `grpclog.LoggerV2` in zapgrpc.
* [***REMOVED***903][]: Support URL-encoded POST requests to the AtomicLevel HTTP handler
  with the `application/x-www-form-urlencoded` content type.
* [***REMOVED***912][]: Support multi-field encoding with `zap.Inline`.
* [***REMOVED***913][]: Speed up SugaredLogger for calls with a single string.
* [***REMOVED***928][]: Add support for filtering by field name to `zaptest/observer`.

Thanks to @ash2k, @FMLS, @jimmystewpot, @Oncilla, @tsoslow, @tylitianrui, @withshubh, and @wziww for their contributions to this release.

[***REMOVED***865]: https://github.com/uber-go/zap/pull/865
[***REMOVED***867]: https://github.com/uber-go/zap/pull/867
[***REMOVED***881]: https://github.com/uber-go/zap/pull/881
[***REMOVED***903]: https://github.com/uber-go/zap/pull/903
[***REMOVED***912]: https://github.com/uber-go/zap/pull/912
[***REMOVED***913]: https://github.com/uber-go/zap/pull/913
[***REMOVED***928]: https://github.com/uber-go/zap/pull/928
[***REMOVED***931]: https://github.com/uber-go/zap/pull/931
[***REMOVED***936]: https://github.com/uber-go/zap/pull/936

***REMOVED******REMOVED*** 1.16.0 (1 Sep 2020)

Bugfixes:
* [***REMOVED***828][]: Fix missing newline in IncreaseLevel error messages.
* [***REMOVED***835][]: Fix panic in JSON encoder when encoding times or durations
  without specifying a time or duration encoder.
* [***REMOVED***843][]: Honor CallerSkip when taking stack traces.
* [***REMOVED***862][]: Fix the default file permissions to use `0666` and rely on the umask instead.
* [***REMOVED***854][]: Encode `<nil>` for nil `Stringer` instead of a panic error log.

Enhancements:
* [***REMOVED***629][]: Added `zapcore.TimeEncoderOfLayout` to easily create time encoders
  for custom layouts.
* [***REMOVED***697][]: Added support for a configurable delimiter in the console encoder.
* [***REMOVED***852][]: Optimize console encoder by pooling the underlying JSON encoder.
* [***REMOVED***844][]: Add ability to include the calling function as part of logs.
* [***REMOVED***843][]: Add `StackSkip` for including truncated stacks as a field.
* [***REMOVED***861][]: Add options to customize Fatal behaviour for better testability.

Thanks to @SteelPhase, @tmshn, @lixingwang, @wyxloading, @moul, @segevfiner, @andy-retailnext and @jcorbin for their contributions to this release.

[***REMOVED***629]: https://github.com/uber-go/zap/pull/629
[***REMOVED***697]: https://github.com/uber-go/zap/pull/697
[***REMOVED***828]: https://github.com/uber-go/zap/pull/828
[***REMOVED***835]: https://github.com/uber-go/zap/pull/835
[***REMOVED***843]: https://github.com/uber-go/zap/pull/843
[***REMOVED***844]: https://github.com/uber-go/zap/pull/844
[***REMOVED***852]: https://github.com/uber-go/zap/pull/852
[***REMOVED***854]: https://github.com/uber-go/zap/pull/854
[***REMOVED***861]: https://github.com/uber-go/zap/pull/861
[***REMOVED***862]: https://github.com/uber-go/zap/pull/862

***REMOVED******REMOVED*** 1.15.0 (23 Apr 2020)

Bugfixes:
* [***REMOVED***804][]: Fix handling of `Time` values out of `UnixNano` range.
* [***REMOVED***812][]: Fix `IncreaseLevel` being reset after a call to `With`.

Enhancements:
* [***REMOVED***806][]: Add `WithCaller` option to supersede the `AddCaller` option. This
  allows disabling annotation of log entries with caller information if
  previously enabled with `AddCaller`.
* [***REMOVED***813][]: Deprecate `NewSampler` constructor in favor of
  `NewSamplerWithOptions` which supports a `SamplerHook` option. This option
   adds support for monitoring sampling decisions through a hook.

Thanks to @danielbprice for their contributions to this release.

[***REMOVED***804]: https://github.com/uber-go/zap/pull/804
[***REMOVED***812]: https://github.com/uber-go/zap/pull/812
[***REMOVED***806]: https://github.com/uber-go/zap/pull/806
[***REMOVED***813]: https://github.com/uber-go/zap/pull/813

***REMOVED******REMOVED*** 1.14.1 (14 Mar 2020)

Bugfixes:
* [***REMOVED***791][]: Fix panic on attempting to build a logger with an invalid Config.
* [***REMOVED***795][]: Vendoring Zap with `go mod vendor` no longer includes Zap's
  development-time dependencies.
* [***REMOVED***799][]: Fix issue introduced in 1.14.0 that caused invalid JSON output to
  be generated for arrays of `time.Time` objects when using string-based time
  formats.

Thanks to @YashishDua for their contributions to this release.

[***REMOVED***791]: https://github.com/uber-go/zap/pull/791
[***REMOVED***795]: https://github.com/uber-go/zap/pull/795
[***REMOVED***799]: https://github.com/uber-go/zap/pull/799

***REMOVED******REMOVED*** 1.14.0 (20 Feb 2020)

Enhancements:
* [***REMOVED***771][]: Optimize calls for disabled log levels.
* [***REMOVED***773][]: Add millisecond duration encoder.
* [***REMOVED***775][]: Add option to increase the level of a logger.
* [***REMOVED***786][]: Optimize time formatters using `Time.AppendFormat` where possible.

Thanks to @caibirdme for their contributions to this release.

[***REMOVED***771]: https://github.com/uber-go/zap/pull/771
[***REMOVED***773]: https://github.com/uber-go/zap/pull/773
[***REMOVED***775]: https://github.com/uber-go/zap/pull/775
[***REMOVED***786]: https://github.com/uber-go/zap/pull/786

***REMOVED******REMOVED*** 1.13.0 (13 Nov 2019)

Enhancements:
* [***REMOVED***758][]: Add `Intp`, `Stringp`, and other similar `*p` field constructors
  to log pointers to primitives with support for `nil` values.

Thanks to @jbizzle for their contributions to this release.

[***REMOVED***758]: https://github.com/uber-go/zap/pull/758

***REMOVED******REMOVED*** 1.12.0 (29 Oct 2019)

Enhancements:
* [***REMOVED***751][]: Migrate to Go modules.

[***REMOVED***751]: https://github.com/uber-go/zap/pull/751

***REMOVED******REMOVED*** 1.11.0 (21 Oct 2019)

Enhancements:
* [***REMOVED***725][]: Add `zapcore.OmitKey` to omit keys in an `EncoderConfig`.
* [***REMOVED***736][]: Add `RFC3339` and `RFC3339Nano` time encoders.

Thanks to @juicemia, @uhthomas for their contributions to this release.

[***REMOVED***725]: https://github.com/uber-go/zap/pull/725
[***REMOVED***736]: https://github.com/uber-go/zap/pull/736

***REMOVED******REMOVED*** 1.10.0 (29 Apr 2019)

Bugfixes:
* [***REMOVED***657][]: Fix `MapObjectEncoder.AppendByteString` not adding value as a
  string.
* [***REMOVED***706][]: Fix incorrect call depth to determine caller in Go 1.12.

Enhancements:
* [***REMOVED***610][]: Add `zaptest.WrapOptions` to wrap `zap.Option` for creating test
  loggers.
* [***REMOVED***675][]: Don't panic when encoding a String field.
* [***REMOVED***704][]: Disable HTML escaping for JSON objects encoded using the
  reflect-based encoder.

Thanks to @iaroslav-ciupin, @lelenanam, @joa, @NWilson for their contributions
to this release.

[***REMOVED***657]: https://github.com/uber-go/zap/pull/657
[***REMOVED***706]: https://github.com/uber-go/zap/pull/706
[***REMOVED***610]: https://github.com/uber-go/zap/pull/610
[***REMOVED***675]: https://github.com/uber-go/zap/pull/675
[***REMOVED***704]: https://github.com/uber-go/zap/pull/704

***REMOVED******REMOVED*** 1.9.1 (06 Aug 2018)

Bugfixes:

* [***REMOVED***614][]: MapObjectEncoder should not ignore empty slices.

[***REMOVED***614]: https://github.com/uber-go/zap/pull/614

***REMOVED******REMOVED*** 1.9.0 (19 Jul 2018)

Enhancements:
* [***REMOVED***602][]: Reduce number of allocations when logging with reflection.
* [***REMOVED***572][], [***REMOVED***606][]: Expose a registry for third-party logging sinks.

Thanks to @nfarah86, @AlekSi, @JeanMertz, @philippgille, @etsangsplk, and
@dimroc for their contributions to this release.

[***REMOVED***602]: https://github.com/uber-go/zap/pull/602
[***REMOVED***572]: https://github.com/uber-go/zap/pull/572
[***REMOVED***606]: https://github.com/uber-go/zap/pull/606

***REMOVED******REMOVED*** 1.8.0 (13 Apr 2018)

Enhancements:
* [***REMOVED***508][]: Make log level configurable when redirecting the standard
  library's logger.
* [***REMOVED***518][]: Add a logger that writes to a `*testing.TB`.
* [***REMOVED***577][]: Add a top-level alias for `zapcore.Field` to clean up GoDoc.

Bugfixes:
* [***REMOVED***574][]: Add a missing import comment to `go.uber.org/zap/buffer`.

Thanks to @DiSiqueira and @djui for their contributions to this release.

[***REMOVED***508]: https://github.com/uber-go/zap/pull/508
[***REMOVED***518]: https://github.com/uber-go/zap/pull/518
[***REMOVED***577]: https://github.com/uber-go/zap/pull/577
[***REMOVED***574]: https://github.com/uber-go/zap/pull/574

***REMOVED******REMOVED*** 1.7.1 (25 Sep 2017)

Bugfixes:
* [***REMOVED***504][]: Store strings when using AddByteString with the map encoder.

[***REMOVED***504]: https://github.com/uber-go/zap/pull/504

***REMOVED******REMOVED*** 1.7.0 (21 Sep 2017)

Enhancements:

* [***REMOVED***487][]: Add `NewStdLogAt`, which extends `NewStdLog` by allowing the user
  to specify the level of the logged messages.

[***REMOVED***487]: https://github.com/uber-go/zap/pull/487

***REMOVED******REMOVED*** 1.6.0 (30 Aug 2017)

Enhancements:

* [***REMOVED***491][]: Omit zap stack frames from stacktraces.
* [***REMOVED***490][]: Add a `ContextMap` method to observer logs for simpler
  field validation in tests.

[***REMOVED***490]: https://github.com/uber-go/zap/pull/490
[***REMOVED***491]: https://github.com/uber-go/zap/pull/491

***REMOVED******REMOVED*** 1.5.0 (22 Jul 2017)

Enhancements:

* [***REMOVED***460][] and [***REMOVED***470][]: Support errors produced by `go.uber.org/multierr`.
* [***REMOVED***465][]: Support user-supplied encoders for logger names.

Bugfixes:

* [***REMOVED***477][]: Fix a bug that incorrectly truncated deep stacktraces.

Thanks to @richard-tunein and @pavius for their contributions to this release.

[***REMOVED***477]: https://github.com/uber-go/zap/pull/477
[***REMOVED***465]: https://github.com/uber-go/zap/pull/465
[***REMOVED***460]: https://github.com/uber-go/zap/pull/460
[***REMOVED***470]: https://github.com/uber-go/zap/pull/470

***REMOVED******REMOVED*** 1.4.1 (08 Jun 2017)

This release fixes two bugs.

Bugfixes:

* [***REMOVED***435][]: Support a variety of case conventions when unmarshaling levels.
* [***REMOVED***444][]: Fix a panic in the observer.

[***REMOVED***435]: https://github.com/uber-go/zap/pull/435
[***REMOVED***444]: https://github.com/uber-go/zap/pull/444

***REMOVED******REMOVED*** 1.4.0 (12 May 2017)

This release adds a few small features and is fully backward-compatible.

Enhancements:

* [***REMOVED***424][]: Add a `LineEnding` field to `EncoderConfig`, allowing users to
  override the Unix-style default.
* [***REMOVED***425][]: Preserve time zones when logging times.
* [***REMOVED***431][]: Make `zap.AtomicLevel` implement `fmt.Stringer`, which makes a
  variety of operations a bit simpler.

[***REMOVED***424]: https://github.com/uber-go/zap/pull/424
[***REMOVED***425]: https://github.com/uber-go/zap/pull/425
[***REMOVED***431]: https://github.com/uber-go/zap/pull/431

***REMOVED******REMOVED*** 1.3.0 (25 Apr 2017)

This release adds an enhancement to zap's testing helpers as well as the
ability to marshal an AtomicLevel. It is fully backward-compatible.

Enhancements:

* [***REMOVED***415][]: Add a substring-filtering helper to zap's observer. This is
  particularly useful when testing the `SugaredLogger`.
* [***REMOVED***416][]: Make `AtomicLevel` implement `encoding.TextMarshaler`.

[***REMOVED***415]: https://github.com/uber-go/zap/pull/415
[***REMOVED***416]: https://github.com/uber-go/zap/pull/416

***REMOVED******REMOVED*** 1.2.0 (13 Apr 2017)

This release adds a gRPC compatibility wrapper. It is fully backward-compatible.

Enhancements:

* [***REMOVED***402][]: Add a `zapgrpc` package that wraps zap's Logger and implements
  `grpclog.Logger`.

[***REMOVED***402]: https://github.com/uber-go/zap/pull/402

***REMOVED******REMOVED*** 1.1.0 (31 Mar 2017)

This release fixes two bugs and adds some enhancements to zap's testing helpers.
It is fully backward-compatible.

Bugfixes:

* [***REMOVED***385][]: Fix caller path trimming on Windows.
* [***REMOVED***396][]: Fix a panic when attempting to use non-existent directories with
  zap's configuration struct.

Enhancements:

* [***REMOVED***386][]: Add filtering helpers to zaptest's observing logger.

Thanks to @moitias for contributing to this release.

[***REMOVED***385]: https://github.com/uber-go/zap/pull/385
[***REMOVED***396]: https://github.com/uber-go/zap/pull/396
[***REMOVED***386]: https://github.com/uber-go/zap/pull/386

***REMOVED******REMOVED*** 1.0.0 (14 Mar 2017)

This is zap's first stable release. All exported APIs are now final, and no
further breaking changes will be made in the 1.x release series. Anyone using a
semver-aware dependency manager should now pin to `^1`.

Breaking changes:

* [***REMOVED***366][]: Add byte-oriented APIs to encoders to log UTF-8 encoded text without
  casting from `[]byte` to `string`.
* [***REMOVED***364][]: To support buffering outputs, add `Sync` methods to `zapcore.Core`,
  `zap.Logger`, and `zap.SugaredLogger`.
* [***REMOVED***371][]: Rename the `testutils` package to `zaptest`, which is less likely to
  clash with other testing helpers.

Bugfixes:

* [***REMOVED***362][]: Make the ISO8601 time formatters fixed-width, which is friendlier
  for tab-separated console output.
* [***REMOVED***369][]: Remove the automatic locks in `zapcore.NewCore`, which allows zap to
  work with concurrency-safe `WriteSyncer` implementations.
* [***REMOVED***347][]: Stop reporting errors when trying to `fsync` standard out on Linux
  systems.
* [***REMOVED***373][]: Report the correct caller from zap's standard library
  interoperability wrappers.

Enhancements:

* [***REMOVED***348][]: Add a registry allowing third-party encodings to work with zap's
  built-in `Config`.
* [***REMOVED***327][]: Make the representation of logger callers configurable (like times,
  levels, and durations).
* [***REMOVED***376][]: Allow third-party encoders to use their own buffer pools, which
  removes the last performance advantage that zap's encoders have over plugins.
* [***REMOVED***346][]: Add `CombineWriteSyncers`, a convenience function to tee multiple
  `WriteSyncer`s and lock the result.
* [***REMOVED***365][]: Make zap's stacktraces compatible with mid-stack inlining (coming in
  Go 1.9).
* [***REMOVED***372][]: Export zap's observing logger as `zaptest/observer`. This makes it
  easier for particularly punctilious users to unit test their application's
  logging.

Thanks to @suyash, @htrendev, @flisky, @Ulexus, and @skipor for their
contributions to this release.

[***REMOVED***366]: https://github.com/uber-go/zap/pull/366
[***REMOVED***364]: https://github.com/uber-go/zap/pull/364
[***REMOVED***371]: https://github.com/uber-go/zap/pull/371
[***REMOVED***362]: https://github.com/uber-go/zap/pull/362
[***REMOVED***369]: https://github.com/uber-go/zap/pull/369
[***REMOVED***347]: https://github.com/uber-go/zap/pull/347
[***REMOVED***373]: https://github.com/uber-go/zap/pull/373
[***REMOVED***348]: https://github.com/uber-go/zap/pull/348
[***REMOVED***327]: https://github.com/uber-go/zap/pull/327
[***REMOVED***376]: https://github.com/uber-go/zap/pull/376
[***REMOVED***346]: https://github.com/uber-go/zap/pull/346
[***REMOVED***365]: https://github.com/uber-go/zap/pull/365
[***REMOVED***372]: https://github.com/uber-go/zap/pull/372

***REMOVED******REMOVED*** 1.0.0-rc.3 (7 Mar 2017)

This is the third release candidate for zap's stable release. There are no
breaking changes.

Bugfixes:

* [***REMOVED***339][]: Byte slices passed to `zap.Any` are now correctly treated as binary blobs
  rather than `[]uint8`.

Enhancements:

* [***REMOVED***307][]: Users can opt into colored output for log levels.
* [***REMOVED***353][]: In addition to hijacking the output of the standard library's
  package-global logging functions, users can now construct a zap-backed
  `log.Logger` instance.
* [***REMOVED***311][]: Frames from common runtime functions and some of zap's internal
  machinery are now omitted from stacktraces.

Thanks to @ansel1 and @suyash for their contributions to this release.

[***REMOVED***339]: https://github.com/uber-go/zap/pull/339
[***REMOVED***307]: https://github.com/uber-go/zap/pull/307
[***REMOVED***353]: https://github.com/uber-go/zap/pull/353
[***REMOVED***311]: https://github.com/uber-go/zap/pull/311

***REMOVED******REMOVED*** 1.0.0-rc.2 (21 Feb 2017)

This is the second release candidate for zap's stable release. It includes two
breaking changes.

Breaking changes:

* [***REMOVED***316][]: Zap's global loggers are now fully concurrency-safe
  (previously, users had to ensure that `ReplaceGlobals` was called before the
  loggers were in use). However, they must now be accessed via the `L()` and
  `S()` functions. Users can update their projects with

  ```
  gofmt -r "zap.L -> zap.L()" -w .
  gofmt -r "zap.S -> zap.S()" -w .
  ```
* [***REMOVED***309][] and [***REMOVED***317][]: RC1 was mistakenly shipped with invalid
  JSON and YAML struct tags on all config structs. This release fixes the tags
  and adds static analysis to prevent similar bugs in the future.

Bugfixes:

* [***REMOVED***321][]: Redirecting the standard library's `log` output now
  correctly reports the logger's caller.

Enhancements:

* [***REMOVED***325][] and [***REMOVED***333][]: Zap now transparently supports non-standard, rich
  errors like those produced by `github.com/pkg/errors`.
* [***REMOVED***326][]: Though `New(nil)` continues to return a no-op logger, `NewNop()` is
  now preferred. Users can update their projects with `gofmt -r 'zap.New(nil) ->
  zap.NewNop()' -w .`.
* [***REMOVED***300][]: Incorrectly importing zap as `github.com/uber-go/zap` now returns a
  more informative error.

Thanks to @skipor and @chapsuk for their contributions to this release.

[***REMOVED***316]: https://github.com/uber-go/zap/pull/316
[***REMOVED***309]: https://github.com/uber-go/zap/pull/309
[***REMOVED***317]: https://github.com/uber-go/zap/pull/317
[***REMOVED***321]: https://github.com/uber-go/zap/pull/321
[***REMOVED***325]: https://github.com/uber-go/zap/pull/325
[***REMOVED***333]: https://github.com/uber-go/zap/pull/333
[***REMOVED***326]: https://github.com/uber-go/zap/pull/326
[***REMOVED***300]: https://github.com/uber-go/zap/pull/300

***REMOVED******REMOVED*** 1.0.0-rc.1 (14 Feb 2017)

This is the first release candidate for zap's stable release. There are multiple
breaking changes and improvements from the pre-release version. Most notably:

* **Zap's import path is now "go.uber.org/zap"** &mdash; all users will
  need to update their code.
* User-facing types and functions remain in the `zap` package. Code relevant
  largely to extension authors is now in the `zapcore` package.
* The `zapcore.Core` type makes it easy for third-party packages to use zap's
  internals but provide a different user-facing API.
* `Logger` is now a concrete type instead of an interface.
* A less verbose (though slower) logging API is included by default.
* Package-global loggers `L` and `S` are included.
* A human-friendly console encoder is included.
* A declarative config struct allows common logger configurations to be managed
  as configuration instead of code.
* Sampling is more accurate, and doesn't depend on the standard library's shared
  timer heap.

***REMOVED******REMOVED*** 0.1.0-beta.1 (6 Feb 2017)

This is a minor version, tagged to allow users to pin to the pre-1.0 APIs and
upgrade at their leisure. Since this is the first tagged release, there are no
backward compatibility concerns and all functionality is new.

Early zap adopters should pin to the 0.1.x minor version until they're ready to
upgrade to the upcoming stable release.
