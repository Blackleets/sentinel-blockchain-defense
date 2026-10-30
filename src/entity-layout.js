/** Deterministic radial layout for a bounded SENTINEL entity neighborhood. */
export function layoutEntityNeighborhood(neighborhood,{width=1100,height=820}={}){
 if(!neighborhood||neighborhood.schema!=="sentinel.entity-neighborhood.v1")throw new TypeError("A SENTINEL entity neighborhood is required");
 if(!Number.isFinite(width)||width<400||width>3000||!Number.isFinite(height)||height<300||height>2400)throw new RangeError("Layout dimensions are outside supported bounds");
 const center={x:width/2,y:height/2},groups=new Map();
 for(const node of neighborhood.nodes||[]){const depth=Number.isInteger(node.distance)?node.distance:0;if(!groups.has(depth))groups.set(depth,[]);groups.get(depth).push(node);}
 const degree=new Map();for(const edge of neighborhood.edges||[]){degree.set(edge.from,(degree.get(edge.from)||0)+1);degree.set(edge.to,(degree.get(edge.to)||0)+1);}
 const positions=new Map();
 for(const [depth,items] of [...groups.entries()].sort((a,b)=>a[0]-b[0])){
  items.sort((a,b)=>a.address.localeCompare(b.address));
  if(depth===0){for(const node of items)positions.set(node.address,{...center,depth,degree:degree.get(node.address)||0,origin:true});continue;}
  const radius=Math.min(Math.min(width,height)*.43,Math.min(width,height)*(.10+depth*.085)+Math.min(items.length*2.2,Math.min(width,height)*.13));
  const phase=(depth%2)*Math.PI/items.length;
  items.forEach((node,index)=>{const angle=-Math.PI/2+phase+(index/items.length)*Math.PI*2;positions.set(node.address,{x:center.x+Math.cos(angle)*radius,y:center.y+Math.sin(angle)*radius,depth,degree:degree.get(node.address)||0,origin:false});});
 }
 return{width,height,center,nodes:[...positions.entries()].map(([address,point])=>({address,...point})),positions:Object.fromEntries(positions)};
}
