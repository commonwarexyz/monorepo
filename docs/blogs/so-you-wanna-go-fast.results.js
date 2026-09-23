// Source: /artifacts/multimmit-measurements.json.zst.
// Transaction-weighted quantiles in milliseconds. Excluded conditions retain only their status.
const results = [
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"crash1","offered_tps":50000,"paper_eligible":true,"achieved_tps":49932.85,"p25_ms":519.047,"p50_ms":603.418,"p75_ms":720.64,"p99_ms":1433.499},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"crash1","offered_tps":100000,"paper_eligible":true,"achieved_tps":99714.35833333334,"p25_ms":514.83,"p50_ms":604.297,"p75_ms":746.038,"p99_ms":2214.905},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"crash1","offered_tps":250000,"paper_eligible":true,"achieved_tps":249400.475,"p25_ms":836.887,"p50_ms":1240.677,"p75_ms":1916.986,"p99_ms":6017.416},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"crash1","offered_tps":500000,"paper_eligible":true,"achieved_tps":501785.7166666667,"p25_ms":1731.467,"p50_ms":2571.326,"p75_ms":3577.945,"p99_ms":9422.77},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"crash9","offered_tps":50000,"paper_eligible":true,"achieved_tps":49955.316666666666,"p25_ms":912.398,"p50_ms":1035.902,"p75_ms":1164.274,"p99_ms":1588.707},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"crash9","offered_tps":100000,"paper_eligible":true,"achieved_tps":101189.075,"p25_ms":902.305,"p50_ms":1040.392,"p75_ms":1198.893,"p99_ms":3476.865},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"crash9","offered_tps":250000,"paper_eligible":true,"achieved_tps":268246.925,"p25_ms":3433.35,"p50_ms":6990.94,"p75_ms":10777.404,"p99_ms":17517.578},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"crash9","offered_tps":500000,"paper_eligible":false,"achieved_tps":312002.025,"p25_ms":null,"p50_ms":null,"p75_ms":null,"p99_ms":null},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"healthy","offered_tps":50000,"paper_eligible":true,"achieved_tps":50026.666666666664,"p25_ms":502.81875,"p50_ms":596.767,"p75_ms":732.942,"p99_ms":1498.249139999997},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"healthy","offered_tps":100000,"paper_eligible":true,"achieved_tps":99980.0,"p25_ms":504.333,"p50_ms":595.1115,"p75_ms":729.2665,"p99_ms":1879.418299999971},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"healthy","offered_tps":250000,"paper_eligible":true,"achieved_tps":249208.33333333334,"p25_ms":690.10825,"p50_ms":898.056,"p75_ms":1682.36675,"p99_ms":4757.093540002875},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"healthy","offered_tps":500000,"paper_eligible":true,"achieved_tps":500441.6666666667,"p25_ms":1800.2035,"p50_ms":2652.047,"p75_ms":4340.182,"p99_ms":13377.167759979815},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":50000,"paper_eligible":true,"achieved_tps":56852.5,"p25_ms":14634.704,"p50_ms":18874.2455,"p75_ms":24447.16975,"p99_ms":41452.74831999888},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":100000,"paper_eligible":true,"achieved_tps":102888.33333333333,"p25_ms":15482.58475,"p50_ms":21366.878,"p75_ms":28151.4575,"p99_ms":60085.232439998515},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":250000,"paper_eligible":false,"achieved_tps":197000.0,"p25_ms":null,"p50_ms":null,"p75_ms":null,"p99_ms":null},
  {"protocol":"BlueBottle","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":500000,"paper_eligible":false,"achieved_tps":208500.0,"p25_ms":null,"p50_ms":null,"p75_ms":null,"p99_ms":null},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash1","offered_tps":50000,"paper_eligible":true,"achieved_tps":49971.2,"p25_ms":339.253,"p50_ms":395.196,"p75_ms":456.694,"p99_ms":582.031},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash1","offered_tps":100000,"paper_eligible":true,"achieved_tps":100070.4,"p25_ms":324.365,"p50_ms":374.9105,"p75_ms":444.205,"p99_ms":581.637},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash1","offered_tps":250000,"paper_eligible":true,"achieved_tps":249843.2,"p25_ms":315.865,"p50_ms":371.661,"p75_ms":430.292,"p99_ms":553.432},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash1","offered_tps":500000,"paper_eligible":true,"achieved_tps":500083.2,"p25_ms":330.414,"p50_ms":391.523,"p75_ms":455.697,"p99_ms":649.786},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash1","offered_tps":1000000,"paper_eligible":true,"achieved_tps":1000243.2,"p25_ms":352.649,"p50_ms":418.741,"p75_ms":487.535,"p99_ms":692.384},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash9","offered_tps":50000,"paper_eligible":true,"achieved_tps":50005.333333333336,"p25_ms":449.25,"p50_ms":544.449,"p75_ms":658.19,"p99_ms":1176.783},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash9","offered_tps":100000,"paper_eligible":true,"achieved_tps":99784.53333333334,"p25_ms":450.85075,"p50_ms":560.185,"p75_ms":700.918,"p99_ms":1139.175},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash9","offered_tps":250000,"paper_eligible":true,"achieved_tps":249826.13333333333,"p25_ms":444.07,"p50_ms":556.176,"p75_ms":702.05175,"p99_ms":1173.866},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash9","offered_tps":500000,"paper_eligible":true,"achieved_tps":498478.93333333335,"p25_ms":485.9015,"p50_ms":613.3765,"p75_ms":777.82525,"p99_ms":1397.529},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"crash9","offered_tps":1000000,"paper_eligible":true,"achieved_tps":1000989.8666666667,"p25_ms":557.50875,"p50_ms":699.811,"p75_ms":861.34525,"p99_ms":1361.296},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"healthy","offered_tps":50000,"paper_eligible":true,"achieved_tps":49988.26666666667,"p25_ms":337.1235,"p50_ms":388.543,"p75_ms":454.42625,"p99_ms":574.0810999999977},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"healthy","offered_tps":100000,"paper_eligible":true,"achieved_tps":100142.93333333333,"p25_ms":314.584,"p50_ms":375.5375,"p75_ms":444.71,"p99_ms":552.076},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"healthy","offered_tps":250000,"paper_eligible":true,"achieved_tps":250205.86666666667,"p25_ms":311.62,"p50_ms":363.9425,"p75_ms":424.324,"p99_ms":548.522},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"healthy","offered_tps":500000,"paper_eligible":true,"achieved_tps":500198.4,"p25_ms":325.0215,"p50_ms":384.8385,"p75_ms":447.6025,"p99_ms":669.0365699998811},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"healthy","offered_tps":1000000,"paper_eligible":true,"achieved_tps":999842.1333333333,"p25_ms":339.082,"p50_ms":400.027,"p75_ms":464.81,"p99_ms":635.173550000295},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":50000,"paper_eligible":true,"achieved_tps":50043.73333333333,"p25_ms":333.3615,"p50_ms":387.3045,"p75_ms":449.1405,"p99_ms":564.5152099999952},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":100000,"paper_eligible":true,"achieved_tps":100036.26666666666,"p25_ms":322.392,"p50_ms":388.395,"p75_ms":442.154,"p99_ms":556.058},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":250000,"paper_eligible":true,"achieved_tps":249890.13333333333,"p25_ms":308.603,"p50_ms":363.0875,"p75_ms":420.478,"p99_ms":541.258},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":500000,"paper_eligible":true,"achieved_tps":500590.93333333335,"p25_ms":323.62375,"p50_ms":383.1135,"p75_ms":445.042,"p99_ms":644.3110999995619},
  {"protocol":"Multimmit","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":1000000,"paper_eligible":true,"achieved_tps":1000042.6666666666,"p25_ms":339.974,"p50_ms":402.23,"p75_ms":467.45225,"p99_ms":676.1822300001234},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash1","offered_tps":50000,"paper_eligible":true,"achieved_tps":49966.933333333334,"p25_ms":349.308,"p50_ms":409.241,"p75_ms":470.555,"p99_ms":610.518},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash1","offered_tps":100000,"paper_eligible":true,"achieved_tps":100066.13333333333,"p25_ms":332.758,"p50_ms":386.457,"p75_ms":462.142,"p99_ms":585.901},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash1","offered_tps":250000,"paper_eligible":true,"achieved_tps":250030.93333333332,"p25_ms":325.66,"p50_ms":382.467,"p75_ms":442.704,"p99_ms":568.878},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash1","offered_tps":500000,"paper_eligible":true,"achieved_tps":499968.0,"p25_ms":343.75,"p50_ms":404.8495,"p75_ms":469.535,"p99_ms":641.527},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash1","offered_tps":1000000,"paper_eligible":true,"achieved_tps":999488.0,"p25_ms":396.677,"p50_ms":474.657,"p75_ms":557.086,"p99_ms":888.346},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash9","offered_tps":50000,"paper_eligible":true,"achieved_tps":50026.666666666664,"p25_ms":456.084,"p50_ms":548.5535,"p75_ms":662.556,"p99_ms":1064.133},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash9","offered_tps":100000,"paper_eligible":true,"achieved_tps":99878.4,"p25_ms":452.2645,"p50_ms":557.0665,"p75_ms":697.84275,"p99_ms":1123.829},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash9","offered_tps":250000,"paper_eligible":true,"achieved_tps":250312.53333333333,"p25_ms":450.88325,"p50_ms":564.4155,"p75_ms":725.03625,"p99_ms":1287.526},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash9","offered_tps":500000,"paper_eligible":true,"achieved_tps":498265.6,"p25_ms":504.70575,"p50_ms":632.9405,"p75_ms":784.1745,"p99_ms":1180.993},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"crash9","offered_tps":1000000,"paper_eligible":true,"achieved_tps":1001617.0666666667,"p25_ms":682.33875,"p50_ms":846.2825,"p75_ms":1037.009,"p99_ms":2661.192},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"healthy","offered_tps":50000,"paper_eligible":true,"achieved_tps":49920.0,"p25_ms":340.8265,"p50_ms":390.4945,"p75_ms":456.227,"p99_ms":576.1046999999844},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"healthy","offered_tps":100000,"paper_eligible":true,"achieved_tps":99985.06666666667,"p25_ms":332.496,"p50_ms":399.064,"p75_ms":455.886,"p99_ms":568.201},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"healthy","offered_tps":250000,"paper_eligible":true,"achieved_tps":249920.0,"p25_ms":317.939,"p50_ms":372.3425,"p75_ms":435.62,"p99_ms":557.341},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"healthy","offered_tps":500000,"paper_eligible":true,"achieved_tps":500253.86666666664,"p25_ms":334.60475,"p50_ms":394.361,"p75_ms":457.64025,"p99_ms":640.4648099996224},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"healthy","offered_tps":1000000,"paper_eligible":true,"achieved_tps":999974.4,"p25_ms":378.73,"p50_ms":451.9025,"p75_ms":528.12225,"p99_ms":800.5470100000053},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"loss_0.001","offered_tps":50000,"paper_eligible":true,"achieved_tps":50133.333333333336,"p25_ms":336.87725,"p50_ms":399.5835,"p75_ms":465.479,"p99_ms":559.975189999951},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"loss_0.001","offered_tps":100000,"paper_eligible":true,"achieved_tps":99938.13333333333,"p25_ms":327.858,"p50_ms":387.9555,"p75_ms":440.131,"p99_ms":561.283},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"loss_0.001","offered_tps":250000,"paper_eligible":true,"achieved_tps":249834.66666666666,"p25_ms":314.13375,"p50_ms":367.2605,"p75_ms":426.05975,"p99_ms":545.893750000123},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"loss_0.001","offered_tps":500000,"paper_eligible":true,"achieved_tps":500074.6666666667,"p25_ms":330.39075,"p50_ms":388.5625,"p75_ms":448.87225,"p99_ms":618.7628299998269},
  {"protocol":"Multimmit","topology":"global","fsync":true,"scenario":"loss_0.001","offered_tps":1000000,"paper_eligible":true,"achieved_tps":999223.4666666667,"p25_ms":361.992,"p50_ms":429.5375,"p75_ms":499.617,"p99_ms":790.936},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"crash1","offered_tps":50000,"paper_eligible":true,"achieved_tps":49965.875,"p25_ms":44.951,"p50_ms":98.545,"p75_ms":178.96,"p99_ms":1229.012},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"crash1","offered_tps":100000,"paper_eligible":true,"achieved_tps":99252.0,"p25_ms":48.931,"p50_ms":97.993,"p75_ms":185.162,"p99_ms":1169.105},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"crash1","offered_tps":250000,"paper_eligible":true,"achieved_tps":250204.38333333333,"p25_ms":72.711,"p50_ms":152.495,"p75_ms":265.927,"p99_ms":1439.509},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"crash1","offered_tps":500000,"paper_eligible":true,"achieved_tps":501607.05,"p25_ms":199.643,"p50_ms":334.787,"p75_ms":586.746,"p99_ms":2610.37},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"crash9","offered_tps":50000,"paper_eligible":true,"achieved_tps":50039.65,"p25_ms":114.344,"p50_ms":194.088,"p75_ms":257.719,"p99_ms":1182.135},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"crash9","offered_tps":100000,"paper_eligible":true,"achieved_tps":100083.36666666667,"p25_ms":155.878,"p50_ms":233.716,"p75_ms":296.003,"p99_ms":1005.002},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"crash9","offered_tps":250000,"paper_eligible":true,"achieved_tps":249166.775,"p25_ms":285.624,"p50_ms":423.031,"p75_ms":619.443,"p99_ms":1576.819},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"crash9","offered_tps":500000,"paper_eligible":true,"achieved_tps":499461.38333333336,"p25_ms":774.62,"p50_ms":999.283,"p75_ms":1267.851,"p99_ms":4768.963},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"healthy","offered_tps":50000,"paper_eligible":true,"achieved_tps":49953.333333333336,"p25_ms":44.0485,"p50_ms":101.872,"p75_ms":176.72025,"p99_ms":1626.5034299999456},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"healthy","offered_tps":100000,"paper_eligible":true,"achieved_tps":99991.66666666667,"p25_ms":46.804,"p50_ms":120.6905,"p75_ms":254.411,"p99_ms":1868.2241899999287},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"healthy","offered_tps":250000,"paper_eligible":true,"achieved_tps":250095.83333333334,"p25_ms":87.5555,"p50_ms":215.81,"p75_ms":540.53175,"p99_ms":2286.0200300011525},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"healthy","offered_tps":500000,"paper_eligible":true,"achieved_tps":503183.3333333333,"p25_ms":162.005,"p50_ms":279.1065,"p75_ms":468.66925,"p99_ms":1554.3862999999374},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":50000,"paper_eligible":true,"achieved_tps":48312.5,"p25_ms":19067.01925,"p50_ms":24204.2725,"p75_ms":30943.263,"p99_ms":55054.269849999575},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":100000,"paper_eligible":true,"achieved_tps":100105.0,"p25_ms":14090.5345,"p50_ms":20849.987,"p75_ms":28913.33775,"p99_ms":113868.23408998316},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":250000,"paper_eligible":false,"achieved_tps":178500.0,"p25_ms":null,"p50_ms":null,"p75_ms":null,"p99_ms":null},
  {"protocol":"BlueBottle","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":500000,"paper_eligible":false,"achieved_tps":182500.0,"p25_ms":null,"p50_ms":null,"p75_ms":null,"p99_ms":null},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash1","offered_tps":50000,"paper_eligible":true,"achieved_tps":50090.666666666664,"p25_ms":42.993,"p50_ms":48.38,"p75_ms":55.907,"p99_ms":67.377},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash1","offered_tps":100000,"paper_eligible":true,"achieved_tps":100019.2,"p25_ms":41.881,"p50_ms":48.174,"p75_ms":55.209,"p99_ms":65.239},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash1","offered_tps":250000,"paper_eligible":true,"achieved_tps":249966.93333333332,"p25_ms":44.351,"p50_ms":48.707,"p75_ms":56.604,"p99_ms":75.745},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash1","offered_tps":500000,"paper_eligible":true,"achieved_tps":500002.13333333336,"p25_ms":47.965,"p50_ms":53.185,"p75_ms":60.985,"p99_ms":76.682},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash1","offered_tps":1000000,"paper_eligible":true,"achieved_tps":999982.9333333333,"p25_ms":53.666,"p50_ms":62.127,"p75_ms":70.506,"p99_ms":102.017},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash9","offered_tps":50000,"paper_eligible":true,"achieved_tps":50030.933333333334,"p25_ms":48.333,"p50_ms":57.0,"p75_ms":69.124,"p99_ms":231.774},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash9","offered_tps":100000,"paper_eligible":true,"achieved_tps":100002.13333333333,"p25_ms":49.55775,"p50_ms":59.1635,"p75_ms":85.72375,"p99_ms":230.17},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash9","offered_tps":250000,"paper_eligible":true,"achieved_tps":249988.26666666666,"p25_ms":57.00675,"p50_ms":75.0715,"p75_ms":137.58,"p99_ms":311.742},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash9","offered_tps":500000,"paper_eligible":true,"achieved_tps":500663.4666666667,"p25_ms":67.9985,"p50_ms":103.744,"p75_ms":173.5625,"p99_ms":503.169},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"crash9","offered_tps":1000000,"paper_eligible":true,"achieved_tps":1000716.8,"p25_ms":93.80975,"p50_ms":163.208,"p75_ms":241.6805,"p99_ms":550.039},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"healthy","offered_tps":50000,"paper_eligible":true,"achieved_tps":49920.0,"p25_ms":44.456,"p50_ms":51.658,"p75_ms":58.21025,"p99_ms":64.4512099999953},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"healthy","offered_tps":100000,"paper_eligible":true,"achieved_tps":100053.33333333333,"p25_ms":44.164,"p50_ms":50.5985,"p75_ms":58.355,"p99_ms":65.27},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"healthy","offered_tps":250000,"paper_eligible":true,"achieved_tps":250026.66666666666,"p25_ms":46.843,"p50_ms":51.164,"p75_ms":59.665,"p99_ms":69.843},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"healthy","offered_tps":500000,"paper_eligible":true,"achieved_tps":500053.3333333333,"p25_ms":47.172,"p50_ms":51.614,"p75_ms":60.577,"p99_ms":76.17702999999374},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"healthy","offered_tps":1000000,"paper_eligible":true,"achieved_tps":1000268.8,"p25_ms":54.452,"p50_ms":62.618,"p75_ms":72.482,"p99_ms":99.79118000009656},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":50000,"paper_eligible":true,"achieved_tps":49920.0,"p25_ms":43.871,"p50_ms":48.8645,"p75_ms":57.29825,"p99_ms":66.67923999999464},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":100000,"paper_eligible":true,"achieved_tps":100053.33333333333,"p25_ms":44.049,"p50_ms":48.6845,"p75_ms":58.261,"p99_ms":66.164},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":250000,"paper_eligible":true,"achieved_tps":250026.66666666666,"p25_ms":46.936,"p50_ms":51.861,"p75_ms":59.894,"p99_ms":70.724},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":500000,"paper_eligible":true,"achieved_tps":499989.3333333333,"p25_ms":47.48875,"p50_ms":52.077,"p75_ms":61.212,"p99_ms":76.45200999999791},
  {"protocol":"Multimmit","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":1000000,"paper_eligible":true,"achieved_tps":999931.7333333333,"p25_ms":54.786,"p50_ms":62.862,"p75_ms":72.766,"p99_ms":96.53809000004829},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash1","offered_tps":50000,"paper_eligible":true,"achieved_tps":50018.13333333333,"p25_ms":48.062,"p50_ms":55.521,"p75_ms":63.306,"p99_ms":80.217},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash1","offered_tps":100000,"paper_eligible":true,"achieved_tps":100019.2,"p25_ms":47.867,"p50_ms":54.8535,"p75_ms":63.167,"p99_ms":78.771},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash1","offered_tps":250000,"paper_eligible":true,"achieved_tps":249975.46666666667,"p25_ms":50.549,"p50_ms":56.064,"p75_ms":66.44,"p99_ms":83.473},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash1","offered_tps":500000,"paper_eligible":true,"achieved_tps":499985.06666666665,"p25_ms":55.287,"p50_ms":62.9795,"p75_ms":70.223,"p99_ms":91.657},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash1","offered_tps":1000000,"paper_eligible":true,"achieved_tps":999872.0,"p25_ms":67.529,"p50_ms":77.478,"p75_ms":88.259,"p99_ms":125.569},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash9","offered_tps":50000,"paper_eligible":true,"achieved_tps":50030.933333333334,"p25_ms":55.702,"p50_ms":65.866,"p75_ms":78.631,"p99_ms":245.367},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash9","offered_tps":100000,"paper_eligible":true,"achieved_tps":99976.53333333334,"p25_ms":55.71475,"p50_ms":66.4885,"p75_ms":92.29175,"p99_ms":258.156},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash9","offered_tps":250000,"paper_eligible":true,"achieved_tps":250197.33333333334,"p25_ms":64.00275,"p50_ms":82.8385,"p75_ms":145.82325,"p99_ms":294.03},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash9","offered_tps":500000,"paper_eligible":true,"achieved_tps":500765.86666666664,"p25_ms":76.49675,"p50_ms":117.9635,"p75_ms":201.39925,"p99_ms":609.388},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"crash9","offered_tps":1000000,"paper_eligible":true,"achieved_tps":996595.2,"p25_ms":99.877,"p50_ms":157.914,"p75_ms":245.877,"p99_ms":662.977},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"healthy","offered_tps":50000,"paper_eligible":true,"achieved_tps":49920.0,"p25_ms":49.97375,"p50_ms":58.163,"p75_ms":64.894,"p99_ms":83.4522099999953},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"healthy","offered_tps":100000,"paper_eligible":true,"achieved_tps":100053.33333333333,"p25_ms":50.425,"p50_ms":60.407,"p75_ms":65.653,"p99_ms":83.756},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"healthy","offered_tps":250000,"paper_eligible":true,"achieved_tps":250026.66666666666,"p25_ms":52.791,"p50_ms":61.9015,"p75_ms":66.885,"p99_ms":84.689},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"healthy","offered_tps":500000,"paper_eligible":true,"achieved_tps":500027.73333333334,"p25_ms":53.219,"p50_ms":62.64,"p75_ms":72.454,"p99_ms":91.25701999999583},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"healthy","offered_tps":1000000,"paper_eligible":true,"achieved_tps":1000034.1333333333,"p25_ms":69.955,"p50_ms":80.624,"p75_ms":91.387,"p99_ms":128.25204000002145},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"loss_0.001","offered_tps":50000,"paper_eligible":true,"achieved_tps":49920.0,"p25_ms":50.40525,"p50_ms":59.4745,"p75_ms":66.122,"p99_ms":86.32619999999552},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"loss_0.001","offered_tps":100000,"paper_eligible":true,"achieved_tps":100049.06666666667,"p25_ms":51.167,"p50_ms":60.405,"p75_ms":65.362,"p99_ms":85.206},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"loss_0.001","offered_tps":250000,"paper_eligible":true,"achieved_tps":250026.66666666666,"p25_ms":52.435,"p50_ms":61.3075,"p75_ms":66.951,"p99_ms":84.449},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"loss_0.001","offered_tps":500000,"paper_eligible":true,"achieved_tps":500151.4666666667,"p25_ms":53.416,"p50_ms":62.8855,"p75_ms":73.021,"p99_ms":92.06800999999791},
  {"protocol":"Multimmit","topology":"na","fsync":true,"scenario":"loss_0.001","offered_tps":1000000,"paper_eligible":true,"achieved_tps":999893.3333333334,"p25_ms":69.966,"p50_ms":80.59,"p75_ms":91.196,"p99_ms":126.70201000000536},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"healthy","offered_tps":50000,"paper_eligible":true,"achieved_tps":49996.666666666664,"p25_ms":108.821,"p50_ms":145.858,"p75_ms":185.936,"p99_ms":228.288},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"healthy","offered_tps":100000,"paper_eligible":true,"achieved_tps":100010.0,"p25_ms":110.961,"p50_ms":147.885,"p75_ms":186.158,"p99_ms":227.644},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"healthy","offered_tps":250000,"paper_eligible":true,"achieved_tps":249999.575,"p25_ms":143.713,"p50_ms":175.305,"p75_ms":218.104,"p99_ms":276.777},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"healthy","offered_tps":500000,"paper_eligible":true,"achieved_tps":499875.0,"p25_ms":210.931,"p50_ms":243.535,"p75_ms":290.576,"p99_ms":367.492},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"crash1","offered_tps":50000,"paper_eligible":true,"achieved_tps":49930.3,"p25_ms":138.6335,"p50_ms":197.187,"p75_ms":443.377,"p99_ms":988.012},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"crash1","offered_tps":100000,"paper_eligible":true,"achieved_tps":99821.79166666667,"p25_ms":139.997,"p50_ms":198.286,"p75_ms":458.983,"p99_ms":985.239},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"crash1","offered_tps":250000,"paper_eligible":true,"achieved_tps":250004.25,"p25_ms":165.169,"p50_ms":222.746,"p75_ms":431.971,"p99_ms":992.45},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"crash1","offered_tps":500000,"paper_eligible":true,"achieved_tps":498422.575,"p25_ms":246.28,"p50_ms":338.555,"p75_ms":674.592,"p99_ms":1080.658},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"crash9","offered_tps":50000,"paper_eligible":true,"achieved_tps":50447.166666666664,"p25_ms":554.226,"p50_ms":1243.799,"p75_ms":1928.755,"p99_ms":2602.486},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"crash9","offered_tps":100000,"paper_eligible":true,"achieved_tps":99045.93333333333,"p25_ms":596.382,"p50_ms":1258.363,"p75_ms":1921.877,"p99_ms":2596.685},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"crash9","offered_tps":250000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"crash9","offered_tps":500000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":50000,"paper_eligible":true,"achieved_tps":50000.0,"p25_ms":113.644,"p50_ms":150.451,"p75_ms":190.196,"p99_ms":233.619},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":100000,"paper_eligible":true,"achieved_tps":100003.33333333333,"p25_ms":113.371,"p50_ms":148.906,"p75_ms":188.411,"p99_ms":233.401},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":250000,"paper_eligible":true,"achieved_tps":249983.33333333334,"p25_ms":143.353,"p50_ms":175.01,"p75_ms":218.998,"p99_ms":276.225},
  {"protocol":"Raptr","topology":"na","fsync":false,"scenario":"loss_0.001","offered_tps":500000,"paper_eligible":true,"achieved_tps":499973.975,"p25_ms":211.666,"p50_ms":244.226,"p75_ms":291.643,"p99_ms":366.058},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"healthy","offered_tps":50000,"paper_eligible":true,"achieved_tps":49993.333333333336,"p25_ms":461.80275,"p50_ms":539.888,"p75_ms":636.14175,"p99_ms":905.7260499999766},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"healthy","offered_tps":100000,"paper_eligible":true,"achieved_tps":99945.0,"p25_ms":460.059,"p50_ms":538.689,"p75_ms":634.856,"p99_ms":909.29},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"healthy","offered_tps":250000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"healthy","offered_tps":500000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"crash1","offered_tps":50000,"paper_eligible":true,"achieved_tps":50062.05,"p25_ms":475.982,"p50_ms":558.894,"p75_ms":670.9,"p99_ms":1393.088},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"crash1","offered_tps":100000,"paper_eligible":true,"achieved_tps":100115.6,"p25_ms":481.941,"p50_ms":571.211,"p75_ms":694.629,"p99_ms":1394.734},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"crash9","offered_tps":50000,"paper_eligible":true,"achieved_tps":50192.10833333333,"p25_ms":635.64,"p50_ms":849.14,"p75_ms":1230.685,"p99_ms":1762.51},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"crash9","offered_tps":100000,"paper_eligible":true,"achieved_tps":100501.36666666667,"p25_ms":6920.47,"p50_ms":7834.671,"p75_ms":8728.357,"p99_ms":10730.305},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":50000,"paper_eligible":true,"achieved_tps":50013.333333333336,"p25_ms":461.112,"p50_ms":541.7,"p75_ms":637.372,"p99_ms":907.282},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":100000,"paper_eligible":true,"achieved_tps":99955.0,"p25_ms":466.017,"p50_ms":545.155,"p75_ms":641.114,"p99_ms":918.887},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"crash1","offered_tps":250000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"crash1","offered_tps":500000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"crash9","offered_tps":250000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"crash9","offered_tps":500000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":250000,"paper_eligible":false},
  {"protocol":"Raptr","topology":"global","fsync":false,"scenario":"loss_0.001","offered_tps":500000,"paper_eligible":false}
];

const NS = 'http://www.w3.org/2000/svg';
const formatTps = value => Math.round(value).toLocaleString('en-US');
const formatMs = value => `${value.toFixed(1)} ms`;

function svgNode(parent, tag, attrs, text = '') {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  node.textContent = text;
  parent.append(node);
  return node;
}

const protocols = ['Multimmit', 'BlueBottle', 'Raptr'];
const colors = ['#1f1fd1', '#ad4b16', '#187647'];

function marker(parent, index, x, y) {
  const attrs = { fill: colors[index], stroke: 'white', 'stroke-width': 1 };
  if (index === 0) return svgNode(parent, 'circle', { cx: x, cy: y, r: 4, ...attrs });
  const d = index === 1 ? `M${x - 4},${y - 4}h8v8h-8Z` : `M${x},${y - 5}l5,9h-10Z`;
  return svgNode(parent, 'path', { d, ...attrs });
}

const panels = document.querySelectorAll('[data-mm-results]');
const renderers = [];
let scenario = 'healthy';
let metric = 'p50_ms';
let fsync = false;
const controlsHost = document.querySelector('[data-mm-results-controls]');
const scenarios = document.createElement('div');
scenarios.className = 'mm-result-scenarios';
scenarios.setAttribute('role', 'group');
scenarios.setAttribute('aria-label', 'Scenario');
for (const [value, text] of [['healthy', 'Healthy'], ['crash1', '1 crash'], ['crash9', '9 crashes'], ['loss_0.001', '0.1% loss']]) {
  const button = document.createElement('button');
  button.textContent = text;
  button.dataset.scenario = value;
  button.addEventListener('click', () => { scenario = value; renderAll(); });
  scenarios.append(button);
}
controlsHost.append(scenarios);
const toolbar = document.createElement('div');
toolbar.className = 'mm-result-toolbar';
controlsHost.append(toolbar);
const controls = document.createElement('div');
controls.className = 'mm-result-controls';
controls.setAttribute('role', 'group');
controls.setAttribute('aria-label', 'Latency statistic');
for (const [key, name] of [['p50_ms', 'Median + P25–P75'], ['p99_ms', 'P99']]) {
  const button = document.createElement('button');
  button.textContent = name;
  button.dataset.metric = key;
  button.addEventListener('click', () => { metric = key; renderAll(); });
  controls.append(button);
}
toolbar.append(controls);
const syncLabel = document.createElement('label');
syncLabel.className = 'mm-result-sync';
const syncInput = document.createElement('input');
syncInput.type = 'checkbox';
syncInput.addEventListener('change', () => { fsync = syncInput.checked; renderAll(); });
syncLabel.append(syncInput, 'Fsync on');
toolbar.append(syncLabel);

function updateControls() {
  for (const button of scenarios.children) button.setAttribute('aria-pressed', button.dataset.scenario === scenario);
  for (const button of controls.children) button.setAttribute('aria-pressed', button.dataset.metric === metric);
  syncInput.checked = fsync;
}

function renderAll() {
  updateControls();
  for (const render of renderers) render();
}

for (const panel of panels) {
  const legend = document.createElement('div');
  legend.className = 'mm-result-legend';
  protocols.forEach((name, index) => {
    const item = document.createElement('span');
    const icon = svgNode(item, 'svg', { viewBox: '0 0 26 14', width: 26, height: 14, 'aria-hidden': 'true' });
    svgNode(icon, 'line', { x1: 0, x2: 26, y1: 7, y2: 7, stroke: colors[index], 'stroke-width': 2 });
    marker(icon, index, 13, 7);
    item.append(name);
    legend.append(item);
  });
  panel.append(legend);
  const plot = document.createElement('div');
  plot.className = 'mm-result-plot';
  panel.append(plot);
  const svg = svgNode(plot, 'svg', {
    role: 'group',
    'aria-label': `${panel.querySelector('h3').textContent}: throughput and scheduled-submission-to-finality latency. Focus a load point to compare implementations.`,
  });
  const tooltip = document.createElement('div');
  tooltip.className = 'mm-result-tooltip';
  tooltip.id = `mm-tooltip-${panel.dataset.mmResults}`;
  tooltip.setAttribute('role', 'tooltip');
  tooltip.hidden = true;
  plot.append(tooltip);
  panel.querySelector('.mm-result-fallback').remove();

  function render() {
    const conditions = results.filter(row => row.topology === panel.dataset.mmResults && row.scenario === scenario && row.fsync === fsync);
    const rows = conditions.filter(row => row.paper_eligible).sort((a, b) => protocols.indexOf(a.protocol) - protocols.indexOf(b.protocol) || a.offered_tps - b.offered_tps);
    for (const [index, item] of [...legend.children].entries()) item.hidden = fsync && protocols[index] !== 'Multimmit';
    const width = plot.clientWidth;
    const height = width < 480 ? 260 : 280;
    const left = 72, right = width - 24, top = 16, bottom = height - 48;
    const minY = 10 ** Math.floor(Math.log10(Math.min(...rows.map(r => metric === 'p50_ms' ? r.p25_ms : r.p99_ms)) / 1.05));
    const upper = Math.max(...rows.map(r => metric === 'p50_ms' ? r.p75_ms : r.p99_ms)) * 1.05;
    const magnitude = 10 ** Math.floor(Math.log10(upper));
    const maxY = [1, 2, 5, 10].map(value => value * magnitude).find(value => value >= upper);
    const x = value => left + value / 1080000 * (right - left);
    const y = value => bottom - Math.log10(value / minY) / Math.log10(maxY / minY) * (bottom - top);
    svg.replaceChildren();
    tooltip.hidden = true;
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    const decoration = svgNode(svg, 'g', { 'aria-hidden': 'true' });
    svgNode(decoration, 'text', {
      transform: `translate(20 ${(top + bottom) / 2}) rotate(-90)`,
      'text-anchor': 'middle', class: 'mm-axis-title',
    }, 'Submission → finality (ms)');
    const ticksY = [];
    for (let power = minY; power <= maxY; power *= 10) {
      for (const multiple of [1, 2, 5]) if (power * multiple <= maxY) ticksY.push(power * multiple);
    }
    for (const tick of ticksY) {
      svgNode(decoration, 'line', { x1: left, y1: y(tick), x2: right, y2: y(tick), class: 'mm-grid' });
      svgNode(decoration, 'text', { x: left - 10, y: y(tick) + 4, 'text-anchor': 'end' }, tick >= 10000 ? `${tick / 1000}k` : tick.toLocaleString('en-US'));
    }
    const ticks = width < 480 ? [0, 500000, 1000000] : [0, 250000, 500000, 750000, 1000000];
    for (const tick of ticks) {
      svgNode(decoration, 'text', { x: x(tick), y: bottom + 20, 'text-anchor': 'middle' }, tick === 1000000 ? '1M' : tick ? `${tick / 1000}k` : '0');
    }
    svgNode(decoration, 'text', { x: (left + right) / 2, y: height - 3, 'text-anchor': 'middle', class: 'mm-axis-title' }, 'Achieved throughput (tx/s)');
    protocols.forEach((protocol, index) => {
      const series = rows.filter(row => row.protocol === protocol);
      if (!series.length) return;
      svgNode(decoration, 'polyline', {
        points: series.map(r => `${x(r.achieved_tps)},${y(r[metric])}`).join(' '),
        fill: 'none', stroke: colors[index], 'stroke-width': 2,
      });
      for (const row of series) {
        const px = x(row.achieved_tps), low = y(row.p25_ms), high = y(row.p75_ms);
        if (metric === 'p50_ms') svgNode(decoration, 'path', {
          d: `M${px},${low}V${high} M${px - 4},${low}h8 M${px - 4},${high}h8`,
          fill: 'none', stroke: colors[index], 'stroke-opacity': .5, 'stroke-width': 1.5,
        });
        marker(decoration, index, px, y(row[metric]));
      }
    });
    const guide = svgNode(decoration, 'line', { y1: top, y2: bottom, class: 'mm-guide', visibility: 'hidden' });
    const hide = () => { tooltip.hidden = true; guide.setAttribute('visibility', 'hidden'); };
    const loads = [...new Set(rows.map(r => r.offered_tps))].sort((a, b) => a - b);
    loads.forEach((load, index) => {
      const group = rows.filter(r => r.offered_tps === load);
      const px = x(load);
      // Group near-overlapping throughput coordinates so every implementation remains inspectable.
      const start = index ? (px + x(loads[index - 1])) / 2 : left;
      const end = index === loads.length - 1 ? right : (px + x(loads[index + 1])) / 2;
      const description = `${formatTps(load)} offered tx/s. ` + group.map(row => `${row.protocol}: ${formatTps(row.achieved_tps)} achieved tx/s, median ${formatMs(row.p50_ms)}, P99 ${formatMs(row.p99_ms)}, P25 ${formatMs(row.p25_ms)}, P75 ${formatMs(row.p75_ms)}.`).join(' ');
      const target = svgNode(svg, 'rect', {
        x: start, y: top, width: end - start, height: bottom - top,
        class: 'mm-hit', tabindex: 0, role: 'button', 'aria-label': description,
      });
      const position = event => {
        if (event?.pointerType === 'mouse' || event?.pointerType === 'pen') {
          const bounds = plot.getBoundingClientRect();
          const gap = 16, edge = 8;
          const w = tooltip.offsetWidth, h = tooltip.offsetHeight;
          let tx = event.clientX + gap, ty = event.clientY + gap;
          if (tx + w > window.innerWidth - edge) tx = event.clientX - gap - w;
          if (ty + h > window.innerHeight - edge) ty = event.clientY - gap - h;
          tx = Math.max(edge, Math.min(tx, window.innerWidth - w - edge));
          ty = Math.max(edge, Math.min(ty, window.innerHeight - h - edge));
          tooltip.style.left = `${tx - bounds.left}px`;
          tooltip.style.top = `${ty - bounds.top}px`;
        } else {
          tooltip.style.left = `${Math.max(0, Math.min(width - tooltip.offsetWidth, px - tooltip.offsetWidth / 2))}px`;
          tooltip.style.top = '22px';
        }
      };
      const show = event => {
        tooltip.innerHTML = `<strong>${formatTps(load)} offered tx/s</strong><table><thead><tr><th>Protocol</th><th>Median</th><th>P99</th></tr></thead><tbody>${group.map(row => `<tr><th style="color:${colors[protocols.indexOf(row.protocol)]}">${row.protocol}</th><td>${formatMs(row.p50_ms)}</td><td>${formatMs(row.p99_ms)}</td></tr><tr><td colspan="3" class="mm-detail">${formatTps(row.achieved_tps)} tx/s · P25–P75: ${row.p25_ms.toFixed(1)}–${formatMs(row.p75_ms)}</td></tr>`).join('')}</tbody></table>`;
        tooltip.hidden = false;
        position(event);
        guide.setAttribute('x1', px);
        guide.setAttribute('x2', px);
        guide.setAttribute('visibility', 'visible');
      };
      target.addEventListener('pointerenter', show);
      target.addEventListener('pointermove', event => { if (!tooltip.hidden) position(event); });
      target.addEventListener('pointerleave', () => { if (document.activeElement !== target) hide(); });
      target.addEventListener('focus', show);
      target.addEventListener('blur', hide);
      target.addEventListener('click', show);
      target.addEventListener('keydown', event => {
        if (event.key === 'Escape') hide();
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); show(); }
      });
    });
  }
  renderers.push(render);
  new ResizeObserver(render).observe(plot);
}
renderAll();
