package p751

// Tools used for testing and debugging

import (
	"fmt"
	. "github.com/cloudflare/circl/dh/sidh/internal/isogeny"
	"math/big"
	"math/rand"
	"reflect"
	"testing/quick"
)

/* -------------------------------------------------------------------------
   Underlying field configuration
   -------------------------------------------------------------------------*/
var (
	kFieldOps = FieldOperations()
	kParams   = &SidhParams{
		Op:      kFieldOps,
		OneFp2:  P751_OneFp2,
		HalfFp2: P751_HalfFp2,
		Bytelen: P751_Bytelen,
	}
	kCurveOps = &CurveOperations{Params: kParams}
)

/* -------------------------------------------------------------------------
   Configure testing/quick
   -------------------------------------------------------------------------*/
var (
	quickCheckScaleFactor = uint8(3)
	quickCheckConfig      = &quick.Config{MaxCount: (1 << (12 + quickCheckScaleFactor))}
)

/* -------------------------------------------------------------------------
   Structure used by tests
   -------------------------------------------------------------------------*/
type GeneratedTestParams struct {
	Point   ProjectivePoint
	Cparam  ProjectiveCurveParameters
	ExtElem Fp2Element
}

/* -------------------------------------------------------------------------
Test values
 -------------------------------------------------------------------------*/

// A = 4385300808024233870220415655826946795549183378139271271040522089756750951667981765872679172832050962894122367066234419550072004266298327417513857609747116903999863022476533671840646615759860564818837299058134292387429068536219*i + 1408083354499944307008104531475821995920666351413327060806684084512082259107262519686546161682384352696826343970108773343853651664489352092568012759783386151707999371397181344707721407830640876552312524779901115054295865393760
var (
	curve_A = Fp2Element{
		A: FpElement{0x8319eb18ca2c435e, 0x3a93beae72cd0267, 0x5e465e1f72fd5a84, 0x8617fa4150aa7272, 0x887da24799d62a13, 0xb079b31b3c7667fe, 0xc4661b150fa14f2e, 0xd4d2b2967bc6efd6, 0x854215a8b7239003, 0x61c5302ccba656c2, 0xf93194a27d6f97a2, 0x1ed9532bca75},
		B: FpElement{0xb6f541040e8c7db6, 0x99403e7365342e15, 0x457e9cee7c29cced, 0x8ece72dc073b1d67, 0x6e73cef17ad28d28, 0x7aed836ca317472, 0x89e1de9454263b54, 0x745329277aa0071b, 0xf623dfc73bc86b9b, 0xb8e3c1d8a9245882, 0x6ad0b3d317770bec, 0x5b406e8d502b}}

	// C = 933177602672972392833143808100058748100491911694554386487433154761658932801917030685312352302083870852688835968069519091048283111836766101703759957146191882367397129269726925521881467635358356591977198680477382414690421049768*i + 9088894745865170214288643088620446862479558967886622582768682946704447519087179261631044546285104919696820250567182021319063155067584445633834024992188567423889559216759336548208016316396859149888322907914724065641454773776307
	curve_C = Fp2Element{
		A: FpElement{0x4fb2358bbf723107, 0x3a791521ac79e240, 0x283e24ef7c4c922f, 0xc89baa1205e33cc, 0x3031be81cff6fee1, 0xaf7a494a2f6a95c4, 0x248d251eaac83a1d, 0xc122fca1e2550c88, 0xbc0451b11b6cfd3d, 0x9c0a114ab046222c, 0x43b957b32f21f6ea, 0x5b9c87fa61de},
		B: FpElement{0xacf142afaac15ec6, 0xfd1322a504a071d5, 0x56bb205e10f6c5c6, 0xe204d2849a97b9bd, 0x40b0122202fe7f2e, 0xecf72c6fafacf2cb, 0x45dfc681f869f60a, 0x11814c9aff4af66c, 0x9278b0c4eea54fe7, 0x9a633d5baf7f2e2e, 0x69a329e6f1a05112, 0x1d874ace23e4}}

	// x(P) = 8172151271761071554796221948801462094972242987811852753144865524899433583596839357223411088919388342364651632180452081960511516040935428737829624206426287774255114241789158000915683252363913079335550843837650671094705509470594*i + 9326574858039944121604015439381720195556183422719505497448541073272720545047742235526963773359004021838961919129020087515274115525812121436661025030481584576474033630899768377131534320053412545346268645085054880212827284581557
	affine_xP = Fp2Element{
		A: FpElement{0xe8d05f30aac47247, 0x576ec00c55441de7, 0xbf1a8ec5fe558518, 0xd77cb17f77515881, 0x8e9852837ee73ec4, 0x8159634ad4f44a6b, 0x2e4eb5533a798c5, 0x9be8c4354d5bc849, 0xf47dc61806496b84, 0x25d0e130295120e0, 0xdbef54095f8139e3, 0x5a724f20862c},
		B: FpElement{0x3ca30d7623602e30, 0xfb281eddf45f07b7, 0xd2bf62d5901a45bc, 0xc67c9baf86306dd2, 0x4e2bd93093f538ca, 0xcfd92075c25b9cbe, 0xceafe9a3095bcbab, 0x7d928ad380c85414, 0x37c5f38b2afdc095, 0x75325899a7b779f4, 0xf130568249f20fdd, 0x178f264767d1}}

	// x([2]P) = 1476586462090705633631615225226507185986710728845281579274759750260315746890216330325246185232948298241128541272709769576682305216876843626191069809810990267291824247158062860010264352034514805065784938198193493333201179504845*i + 3623708673253635214546781153561465284135688791018117615357700171724097420944592557655719832228709144190233454198555848137097153934561706150196041331832421059972652530564323645509890008896574678228045006354394485640545367112224
	affine_xP2 = Fp2Element{
		A: FpElement{0x2a77afa8576ce979, 0xab1360e69b0aeba0, 0xd79e3e3cbffad660, 0x5fd0175aa10f106b, 0x1800ebafce9fbdbc, 0x228fc9142bdd6166, 0x867cf907314e34c3, 0xa58d18c94c13c31c, 0x699a5bc78b11499f, 0xa29fc29a01f7ccf1, 0x6c69c0c5347eebce, 0x38ecee0cc57},
		B: FpElement{0x43607fd5f4837da0, 0x560bad4ce27f8f4a, 0x2164927f8495b4dd, 0x621103fdb831a997, 0xad740c4eea7db2db, 0x2cde0442205096cd, 0x2af51a70ede8324e, 0x41a4e680b9f3466, 0x5481f74660b8f476, 0xfcb2f3e656ff4d18, 0x42e3ce0837171acc, 0x44238c30530c}}

	// x([3]P) = 9351941061182433396254169746041546943662317734130813745868897924918150043217746763025923323891372857734564353401396667570940585840576256269386471444236630417779544535291208627646172485976486155620044292287052393847140181703665*i + 9010417309438761934687053906541862978676948345305618417255296028956221117900864204687119686555681136336037659036201780543527957809743092793196559099050594959988453765829339642265399496041485088089691808244290286521100323250273
	affine_xP3 = Fp2Element{
		A: FpElement{0x2096e3f23feca947, 0xf36f635aa4ad8634, 0xdae3b1c6983c5e9a, 0xe08df6c262cb74b4, 0xd2ca4edc37452d3d, 0xfb5f3fe42f500c79, 0x73740aa3abc2b21f, 0xd535fd869f914cca, 0x4a558466823fb67f, 0x3e50a7a0e3bfc715, 0xf43c6da9183a132f, 0x61aca1e1b8b9},
		B: FpElement{0x1e54ec26ea5077bd, 0x61380572d8769f9a, 0xc615170684f59818, 0x6309c3b93e84ef6e, 0x33c74b1318c3fcd0, 0xfe8d7956835afb14, 0x2d5a7b55423c1ecc, 0x869db67edfafea68, 0x1292632394f0a628, 0x10bba48225bfd141, 0x6466c28b408daba, 0x63cacfdb7c43}}

	// x([2^2]P) = 441719501189485559222919502512761433931671682884872259563221427434901842337947564993718830905758163254463901652874331063768876314142359813382575876106725244985607032091781306919778265250690045578695338669105227100119314831452*i + 6961734028200975729170216310486458180126343885294922940439352055937945948015840788921225114530454649744697857047401608073256634790353321931728699534700109268264491160589480994022419317695690866764726967221310990488404411684053
	affine_xP4 = Fp2Element{
		A: FpElement{0x6f9dbe4c39175153, 0xf2fec757eb99e88, 0x43d7361a93733d91, 0x3abd10ed19c85a3d, 0xc4de9ab9c5ef7181, 0x53e375901684c900, 0x68ffc3e7d71c41ff, 0x47adab62c8d942fe, 0x226a33fd6fbb381d, 0x87ef4c8fdd83309a, 0xaca1cf44c5fa8799, 0x6cbae86c755f},
		B: FpElement{0x4c80c37fe68282a7, 0xbd8b9d7248bf553a, 0x1fb0e8e74d5e1762, 0xb63fa0e4e5f91482, 0xc675ab8a45a1439, 0xdfa6772deace7820, 0xf0d813d71d9a9255, 0x53a1a58c634534bd, 0x4ebfc6485fdfd888, 0x6991fe4358bcf169, 0xc0547bdaca85b6fd, 0xf461548d632}}

	// x([3^2]P) = 3957171963425208493644602380039721164492341594850197356580248639045894821895524981729970650520936632013218950972842867220898274664982599375786979902471523505057611521217523103474682939638645404445093536997296151472632038973463*i + 1357869545269286021642168835877253886774707209614159162748874474269328421720121175566245719916322684751967981171882659798149072149161259103020057556362998810229937432814792024248155991141511691087135859252304684633946087474060
	affine_xP9 = Fp2Element{
		A: FpElement{0x7c0daa0f04ded4e0, 0x52dc4f883d85e065, 0x91afbdc2c1714d0b, 0xb7b3db8e658cfeba, 0x43d4e72a692882f3, 0x535c56d83753da30, 0xc8a58724433cbf5d, 0x351153c0a5e74219, 0x2c81827d19f93dd5, 0x26ef8aca3370ea1a, 0x1cf939a6dd225dec, 0x3403cb28ad41},
		B: FpElement{0x93e7bc373a9ff7b, 0x57b8cc47635ebc0f, 0x92eab55689106cf3, 0x93643111d421f24c, 0x1c58b519506f6b7a, 0xebd409fb998faa13, 0x5c86ed799d09d80e, 0xd9a1d764d6363562, 0xf95e87f92fb0c4cc, 0x6b2bbaf5632a5609, 0x2d9b6a809dfaff7f, 0x29c0460348b}}

	// m = 96550223052359874398280314003345143371473380422728857598463622014420884224892
	mScalarBytes = [...]uint8{0x7c, 0x7b, 0x95, 0xfa, 0xb4, 0x75, 0x6c, 0x48, 0x8c, 0x17, 0x55, 0xb4, 0x49, 0xf5, 0x1e, 0xa3, 0xb, 0x31, 0xf0, 0xa4, 0xa6, 0x81, 0xad, 0x94, 0x51, 0x11, 0xe7, 0xf5, 0x5b, 0x7d, 0x75, 0xd5}

	// x([m]P) = 7893578558852400052689739833699289348717964559651707250677393044951777272628231794999463214496545377542328262828965953246725804301238040891993859185944339366910592967840967752138115122568615081881937109746463885908097382992642*i + 8293895847098220389503562888233557012043261770526854885191188476280014204211818299871679993460086974249554528517413590157845430186202704783785316202196966198176323445986064452630594623103149383929503089342736311904030571524837
	affine_xaP = Fp2Element{
		A: FpElement{0x2112f3c7d7f938bb, 0x704a677f0a4df08f, 0x825370e31fb4ef00, 0xddbf79b7469f902, 0x27640c899ea739fd, 0xfb7b8b19f244108e, 0x546a6679dd3baebc, 0xe9f0ecf398d5265f, 0x223d2b350e75e461, 0x84b322a0b6aff016, 0xfabe426f539f8b39, 0x4507a0604f50},
		B: FpElement{0xac77737e5618a5fe, 0xf91c0e08c436ca52, 0xd124037bc323533c, 0xc9a772bf52c58b63, 0x3b30c8f38ef6af4d, 0xb9eed160e134f36e, 0x24e3836393b25017, 0xc828be1b11baf1d9, 0x7b7dab585df50e93, 0x1ca3852c618bd8e0, 0x4efa73bcb359fa00, 0x50b6a923c2d4}}

	// Inputs for testing 3-point-ladder
	threePointLadderInputs = []ProjectivePoint{
		// x(P)
		ProjectivePoint{
			X: Fp2Element{
				A: FpElement{0xe8d05f30aac47247, 0x576ec00c55441de7, 0xbf1a8ec5fe558518, 0xd77cb17f77515881, 0x8e9852837ee73ec4, 0x8159634ad4f44a6b, 0x2e4eb5533a798c5, 0x9be8c4354d5bc849, 0xf47dc61806496b84, 0x25d0e130295120e0, 0xdbef54095f8139e3, 0x5a724f20862c},
				B: FpElement{0x3ca30d7623602e30, 0xfb281eddf45f07b7, 0xd2bf62d5901a45bc, 0xc67c9baf86306dd2, 0x4e2bd93093f538ca, 0xcfd92075c25b9cbe, 0xceafe9a3095bcbab, 0x7d928ad380c85414, 0x37c5f38b2afdc095, 0x75325899a7b779f4, 0xf130568249f20fdd, 0x178f264767d1}},
			Z: P751_OneFp2,
		},
		// x(Q)
		ProjectivePoint{
			X: Fp2Element{
				A: FpElement{0x2b71a2a93ad1e10e, 0xf0b9842a92cfb333, 0xae17373615a27f5c, 0x3039239f428330c4, 0xa0c4b735ed7dcf98, 0x6e359771ddf6af6a, 0xe986e4cac4584651, 0x8233a2b622d5518, 0xbfd67bf5f06b818b, 0xdffe38d0f5b966a6, 0xa86b36a3272ee00a, 0x193e2ea4f68f},
				B: FpElement{0x5a0f396459d9d998, 0x479f42250b1b7dda, 0x4016b57e2a15bf75, 0xc59f915203fa3749, 0xd5f90257399cf8da, 0x1fb2dadfd86dcef4, 0x600f20e6429021dc, 0x17e347d380c57581, 0xc1b0d5fa8fe3e440, 0xbcf035330ac20e8, 0x50c2eb5f6a4f03e6, 0x86b7c4571}},
			Z: P751_OneFp2,
		},
		// x(P-Q)
		ProjectivePoint{
			X: Fp2Element{
				A: FpElement{0x4aafa9f378f7b5ff, 0x1172a683aa8eee0, 0xea518d8cbec2c1de, 0xe191bcbb63674557, 0x97bc19637b259011, 0xdbeae5c9f4a2e454, 0x78f64d1b72a42f95, 0xe71cb4ea7e181e54, 0xe4169d4c48543994, 0x6198c2286a98730f, 0xd21d675bbab1afa5, 0x2e7269fce391},
				B: FpElement{0x23355783ce1d0450, 0x683164cf4ce3d93f, 0xae6d1c4d25970fd8, 0x7807007fb80b48cf, 0xa005a62ec2bbb8a2, 0x6b5649bd016004cb, 0xbb1a13fa1330176b, 0xbf38e51087660461, 0xe577fddc5dd7b930, 0x5f38116f56947cd3, 0x3124f30b98c36fde, 0x4ca9b6e6db37}},
			Z: P751_OneFp2,
		},
	}
	curve         = ProjectiveCurveParameters{A: curve_A, C: curve_C}
	cln16prime, _ = new(big.Int).SetString("10354717741769305252977768237866805321427389645549071170116189679054678940682478846502882896561066713624553211618840202385203911976522554393044160468771151816976706840078913334358399730952774926980235086850991501872665651576831", 10)
)

/* -------------------------------------------------------------------------
   Values used by benchmarking tools
   -------------------------------------------------------------------------*/

// Package-level storage for this field element is intended to deter
// compiler optimizations.
var (
	benchmarkFpElement   FpElement
	benchmarkFpElementX2 FpElementX2
	bench_x              = FpElement{17026702066521327207, 5108203422050077993, 10225396685796065916, 11153620995215874678, 6531160855165088358, 15302925148404145445, 1248821577836769963, 9789766903037985294, 7493111552032041328, 10838999828319306046, 18103257655515297935, 27403304611634}
	bench_y              = FpElement{4227467157325093378, 10699492810770426363, 13500940151395637365, 12966403950118934952, 16517692605450415877, 13647111148905630666, 14223628886152717087, 7167843152346903316, 15855377759596736571, 4300673881383687338, 6635288001920617779, 30486099554235}
	bench_z              = FpElementX2{1595347748594595712, 10854920567160033970, 16877102267020034574, 12435724995376660096, 3757940912203224231, 8251999420280413600, 3648859773438820227, 17622716832674727914, 11029567000887241528, 11216190007549447055, 17606662790980286987, 4720707159513626555, 12887743598335030915, 14954645239176589309, 14178817688915225254, 1191346797768989683, 12629157932334713723, 6348851952904485603, 16444232588597434895, 7809979927681678066, 14642637672942531613, 3092657597757640067, 10160361564485285723, 240071237}
)

// Helpers
func (primeElement primeFieldElement) String() string {
	b := toBigInt(&primeElement.A)
	return fmt.Sprintf("%X", b.String())
}

/* -------------------------------------------------------------------------
   Helpers
   -------------------------------------------------------------------------*/

// Given xP = x(P), xQ = x(Q), and xPmQ = x(P-Q), compute xR = x(P+Q).
//
// Returns xR to allow chaining.  Safe to overlap xP, xQ, xR.
func AddProjFp2(xP, xQ, xPmQ *ProjectivePoint) ProjectivePoint {
	// Algorithm 1 of Costello-Smith.
	var v0, v1, v2, v3, v4 Fp2Element
	var xR ProjectivePoint
	kFieldOps.Add(&v0, &xP.X, &xP.Z) // X_P + Z_P
	kFieldOps.Sub(&v1, &xQ.X, &xQ.Z)
	kFieldOps.Mul(&v1, &v1, &v0)     // (X_Q - Z_Q)(X_P + Z_P)
	kFieldOps.Sub(&v0, &xP.X, &xP.Z) // X_P - Z_P
	kFieldOps.Add(&v2, &xQ.X, &xQ.Z)
	kFieldOps.Mul(&v2, &v2, &v0) // (X_Q + Z_Q)(X_P - Z_P)
	kFieldOps.Add(&v3, &v1, &v2)
	kFieldOps.Square(&v3, &v3) // 4(X_Q X_P - Z_Q Z_P)^2
	kFieldOps.Sub(&v4, &v1, &v2)
	kFieldOps.Square(&v4, &v4)         // 4(X_Q Z_P - Z_Q X_P)^2
	kFieldOps.Mul(&v0, &xPmQ.Z, &v3)   // 4X_{P-Q}(X_Q X_P - Z_Q Z_P)^2
	kFieldOps.Mul(&xR.Z, &xPmQ.X, &v4) // 4Z_{P-Q}(X_Q Z_P - Z_Q X_P)^2
	xR.X = v0
	return xR
}

// Given xP = x(P) and cached curve parameters Aplus2C = A + 2*C, C4 = 4*C,
// compute xQ = x([2]P).
//
// Returns xQ to allow chaining.  Safe to overlap xP, xQ.
func DoubleProjFp2(xP *ProjectivePoint, Aplus2C, C4 *Fp2Element) ProjectivePoint {
	// Algorithm 2 of Costello-Smith, amended to work with projective curve coefficients.
	var v1, v2, v3, xz4 Fp2Element
	var xQ ProjectivePoint
	kFieldOps.Add(&v1, &xP.X, &xP.Z) // (X+Z)^2
	kFieldOps.Square(&v1, &v1)
	kFieldOps.Sub(&v2, &xP.X, &xP.Z) // (X-Z)^2
	kFieldOps.Square(&v2, &v2)
	kFieldOps.Sub(&xz4, &v1, &v2)     // 4XZ = (X+Z)^2 - (X-Z)^2
	kFieldOps.Mul(&v2, &v2, C4)       // 4C(X-Z)^2
	kFieldOps.Mul(&xQ.X, &v1, &v2)    // 4C(X+Z)^2(X-Z)^2
	kFieldOps.Mul(&v3, &xz4, Aplus2C) // 4XZ(A + 2C)
	kFieldOps.Add(&v3, &v3, &v2)      // 4XZ(A + 2C) + 4C(X-Z)^2
	kFieldOps.Mul(&xQ.Z, &v3, &xz4)   // (4XZ(A + 2C) + 4C(X-Z)^2)4XZ
	// Now (xQ.x : xQ.z)
	//   = (4C(X+Z)^2(X-Z)^2 : (4XZ(A + 2C) + 4C(X-Z)^2)4XZ )
	//   = ((X+Z)^2(X-Z)^2 : (4XZ((A + 2C)/4C) + (X-Z)^2)4XZ )
	//   = ((X+Z)^2(X-Z)^2 : (4XZ((a + 2)/4) + (X-Z)^2)4XZ )
	return xQ
}

// Given x(P) and a scalar m in little-endian bytes, compute x([m]P) using the
// Montgomery ladder.  This is described in Algorithm 8 of Costello-Smith.
//
// This function's execution time is dependent only on the byte-length of the
// input scalar.  All scalars of the same input length execute in uniform time.
// The scalar can be padded with zero bytes to ensure a uniform length.
//
// Safe to overlap the source with the destination.
func ScalarMult(curve *ProjectiveCurveParameters, xP *ProjectivePoint, scalar []uint8) ProjectivePoint {
	var x0, x1, tmp ProjectivePoint
	var Aplus2C, C4 Fp2Element

	kFieldOps.Add(&Aplus2C, &curve.C, &curve.C) // = 2*C
	kFieldOps.Add(&C4, &Aplus2C, &Aplus2C)      // = 4*C
	kFieldOps.Add(&Aplus2C, &Aplus2C, &curve.A) // = 2*C + A

	x0.X = P751_OneFp2
	x1 = *xP

	// Iterate over the bits of the scalar, top to bottom
	prevBit := uint8(0)
	for i := len(scalar) - 1; i >= 0; i-- {
		scalarByte := scalar[i]
		for j := 7; j >= 0; j-- {
			bit := (scalarByte >> uint(j)) & 0x1
			kCurveOps.Params.Op.CondSwap(&x0.X, &x0.Z, &x1.X, &x1.Z, (bit ^ prevBit))
			//sProjectivePointConditionalSwap(&x0, &x1, (bit ^ prevBit))
			tmp = DoubleProjFp2(&x0, &Aplus2C, &C4)
			x1 = AddProjFp2(&x0, &x1, xP)
			x0 = tmp
			prevBit = bit
		}
	}
	// now prevBit is the lowest bit of the scalar
	kCurveOps.Params.Op.CondSwap(&x0.X, &x0.Z, &x1.X, &x1.Z, prevBit)
	return x0
}

// Returns true if lhs = rhs.  Takes variable time.
func VartimeEqFp2(lhs, rhs *Fp2Element) bool {
	a := *lhs
	b := *rhs

	fp751StrongReduce(&a.A)
	fp751StrongReduce(&a.B)
	fp751StrongReduce(&b.A)
	fp751StrongReduce(&b.B)

	eq := true
	for i := 0; i < len(a.A) && eq; i++ {
		eq = eq && (a.A[i] == b.A[i])
		eq = eq && (a.B[i] == b.B[i])
	}
	return eq
}

// Returns true if lhs = rhs.  Takes variable time.
func VartimeEqProjFp2(lhs, rhs *ProjectivePoint) bool {
	var t0, t1 Fp2Element
	kFieldOps.Mul(&t0, &lhs.X, &rhs.Z)
	kFieldOps.Mul(&t1, &lhs.Z, &rhs.X)
	return VartimeEqFp2(&t0, &t1)
}

func (GeneratedTestParams) generateFp2p751(rand *rand.Rand) Fp2Element {
	// Generation strategy: low limbs taken from [0,2^64); high limb
	// taken from smaller range
	//
	// Size hint is ignored since all elements are fixed size.
	//
	// Field elements taken in range [0,2p).  Emulate this by capping
	// the high limb by the top digit of 2*p-1:
	//
	// sage: (2*p-1).digits(2^64)[-1]
	// 246065832128056
	//
	// This still allows generating values >= 2p, but hopefully that
	// excess is OK (and if it's not, we'll find out, because it's for
	// testing...)
	//
	highLimb := rand.Uint64() % 246065832128056
	fpElementGen := func() FpElement {
		return FpElement{
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			rand.Uint64(),
			highLimb,
		}
	}
	return Fp2Element{A: fpElementGen(), B: fpElementGen()}
}

func (c GeneratedTestParams) Generate(rand *rand.Rand, size int) reflect.Value {
	return reflect.ValueOf(
		GeneratedTestParams{
			ProjectivePoint{
				X: c.generateFp2p751(rand),
				Z: c.generateFp2p751(rand),
			},
			ProjectiveCurveParameters{
				A: c.generateFp2p751(rand),
				C: c.generateFp2p751(rand),
			},
			c.generateFp2p751(rand),
		})
}

func (x primeFieldElement) Generate(rand *rand.Rand, size int) reflect.Value {
	return reflect.ValueOf(primeFieldElement{
		A: new(GeneratedTestParams).generateFp2p751(rand).A})
}

// Convert an FpElement to a big.Int for testing.  Because this is only
// for testing, no big.Int to FpElement conversion is provided.
func radix64ToBigInt(x []uint64) *big.Int {
	radix := new(big.Int)
	// 2^64
	radix.UnmarshalText(([]byte)("18446744073709551616"))

	base := new(big.Int).SetUint64(1)
	val := new(big.Int).SetUint64(0)
	tmp := new(big.Int)

	for _, xi := range x {
		tmp.SetUint64(xi)
		tmp.Mul(tmp, base)
		val.Add(val, tmp)
		base.Mul(base, radix)
	}

	return val
}

// Converts number from Montgomery domain and returns big.Int
func toBigInt(x *FpElement) *big.Int {
	var fp Fp2Element
	var in = Fp2Element{A: *x}
	kFieldOps.FromMontgomery(&in, &fp)
	return radix64ToBigInt(fp.A[:])
}
