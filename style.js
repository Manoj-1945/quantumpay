// Quantum particle canvas for landing page
(function(){
  const canvas = document.getElementById('qcanvas');
  if(!canvas) return;
  const ctx = canvas.getContext('2d');
  let W, H, particles=[];

  function resize(){
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  class P{
    constructor(){this.reset()}
    reset(){
      this.x=Math.random()*W; this.y=Math.random()*H;
      this.vx=(Math.random()-.5)*.5; this.vy=(Math.random()-.5)*.5;
      this.r=Math.random()*1.5+.5;
      this.hue=Math.random()>.5?190:270;
      this.alpha=Math.random()*.4+.1;
    }
    update(){
      this.x+=this.vx; this.y+=this.vy;
      if(this.x<0||this.x>W)this.vx*=-1;
      if(this.y<0||this.y>H)this.vy*=-1;
    }
    draw(){
      ctx.beginPath();
      ctx.arc(this.x,this.y,this.r,0,Math.PI*2);
      ctx.fillStyle=`hsla(${this.hue},100%,70%,${this.alpha})`;
      ctx.fill();
    }
  }
  for(let i=0;i<100;i++) particles.push(new P());

  function frame(){
    ctx.clearRect(0,0,W,H);
    for(let i=0;i<particles.length;i++){
      particles[i].update();
      particles[i].draw();
      for(let j=i+1;j<particles.length;j++){
        const dx=particles[i].x-particles[j].x;
        const dy=particles[i].y-particles[j].y;
        const d=Math.sqrt(dx*dx+dy*dy);
        if(d<120){
          ctx.beginPath();
          ctx.moveTo(particles[i].x,particles[i].y);
          ctx.lineTo(particles[j].x,particles[j].y);
          ctx.strokeStyle=`rgba(0,245,255,${(1-d/120)*.15})`;
          ctx.lineWidth=.5;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(frame);
  }
  frame();

  // Animate hero stats counter
  document.querySelectorAll('.hstat-val').forEach(el=>{
    const txt = el.textContent;
    if(txt==='0'){
      let v=1234; el.textContent=v;
      setInterval(()=>{ el.textContent=0; },2000);
    }
  });
})();
